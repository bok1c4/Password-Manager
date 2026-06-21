#include "sharing/rewrap.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <stdexcept>

#include <openssl/crypto.h>

#include "crypto/aes.h"
#include "crypto/encryptor.h"
#include "crypto/envelope.h"
#include "crypto/gpg.h"
#include "crypto/secret.h"

namespace pwmgr::sharing {

namespace {

// Sort a recipient set ascending by device id so recipients.front() is the
// deterministic lowest-id member (the per-entry legacy recipient).
void sort_by_id(std::vector<db::Device>& devices) {
  std::sort(devices.begin(), devices.end(),
            [](const db::Device& a, const db::Device& b) { return a.id < b.id; });
}

// Wrap the raw 32-byte key to a CHOSEN recipient set + the legacy aes_key.
// The legacy recipient is the lowest-id device in the set (so a device outside
// the set cannot read via the fallback — no founding backdoor). With an empty
// set (pre-migration DB) the legacy recipient is the caller's own fingerprint,
// preserving today's single-wrap write. `recipients` must already be sorted by
// id. `legacy_out` receives the aes_key wrap; returns the per-device wraps.
std::vector<db::WrappedKey> wrap_to_set(const std::string& raw_key,
                                        const std::vector<db::Device>& recipients,
                                        std::string_view my_fingerprint,
                                        std::string& legacy_out) {
  const std::string legacy_fpr = recipients.empty()
                                     ? std::string(my_fingerprint)
                                     : recipients.front().fingerprint;
  if (legacy_fpr.empty()) {
    throw std::runtime_error("no recipient fingerprint available for encrypt");
  }
  legacy_out = crypto::gpg_encrypt_to_fingerprint(raw_key, legacy_fpr);
  std::vector<db::WrappedKey> wraps;
  wraps.reserve(recipients.size());
  for (const auto& d : recipients) {
    wraps.push_back(
        {d.id, crypto::gpg_encrypt_to_fingerprint(raw_key, d.fingerprint)});
  }
  return wraps;
}

// Per-(entry, device) grant primitive: unwrap K with MY key, wrap it to
// `target`, insert the row. Shared by enroll (all entries) and `entry grant`
// (one entry). Cleanses the raw key on every path.
void grant_one(KeyStore& store, std::string_view my_fingerprint,
               std::int64_t id, const db::Device& target) {
  const std::string wrap = store.wrapped_key_for(id, my_fingerprint);
  std::string k = crypto::gpg_decrypt(wrap);
  if (k.size() != 32) {
    OPENSSL_cleanse(k.data(), k.size());
    throw std::runtime_error("entry " + std::to_string(id) +
                             ": unwrapped AES key is not 32 bytes");
  }
  std::string rewrapped;
  try {
    rewrapped = crypto::gpg_encrypt_to_fingerprint(k, target.fingerprint);
  } catch (...) {
    OPENSSL_cleanse(k.data(), k.size());
    throw;
  }
  OPENSSL_cleanse(k.data(), k.size());
  store.insert_wrapped_key(id, target.id, rewrapped);
}

// Rotate ONE entry to EXACTLY `recipients` (already sorted by id): decrypt with
// my wrap, fresh K, re-encrypt v2 GCM, wrap to the set + legacy, replace wraps.
// `was_v1_out` (optional) reports whether the prior blob was a v1 row.
void rotate_one(KeyStore& store, std::string_view my_fingerprint,
                std::int64_t id, const std::vector<db::Device>& recipients,
                bool* was_v1_out) {
  const db::Entry e = store.get_entry(id);
  const bool was_v1 = crypto::parse_password_blob(e.password_blob).version ==
                      crypto::Version::V1_Cbc;
  const std::string wrap = store.wrapped_key_for(id, my_fingerprint);
  crypto::Encryptor dec("");  // recipient unused on the decrypt path
  std::string plaintext = dec.decrypt(e.password_blob, wrap);

  crypto::SecureBytes k(crypto::random_bytes(32));
  std::string blob;
  try {
    blob = crypto::serialize_v2(crypto::aes256_gcm_encrypt(plaintext, k.bytes()));
  } catch (...) {
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    throw;
  }
  OPENSSL_cleanse(plaintext.data(), plaintext.size());

  std::string raw_key(reinterpret_cast<const char*>(k.bytes().data()),
                      k.bytes().size());
  std::string legacy_wrap;
  std::vector<db::WrappedKey> wraps;
  try {
    wraps = wrap_to_set(raw_key, recipients, my_fingerprint, legacy_wrap);
  } catch (...) {
    OPENSSL_cleanse(raw_key.data(), raw_key.size());
    throw;
  }
  OPENSSL_cleanse(raw_key.data(), raw_key.size());

  store.replace_entry_keys(id, blob, legacy_wrap, 2, wraps);
  if (was_v1_out) *was_v1_out = was_v1;
}

}  // namespace

std::string RepositoryKeyStore::wrapped_key_for(std::int64_t id,
                                                std::string_view fingerprint) {
  auto w = repo_->wrapped_key_for(id, fingerprint);
  if (!w) {
    throw std::runtime_error("entry " + std::to_string(id) +
                             ": no wrapped key found (entry gone?)");
  }
  return *w;
}

db::Entry RepositoryKeyStore::get_entry(std::int64_t id) {
  auto e = repo_->get_entry(id);
  if (!e) {
    throw std::runtime_error("entry " + std::to_string(id) + " does not exist");
  }
  return *e;
}

void ensure_device_keys_local(const std::vector<db::Device>& devices) {
  for (const auto& d : devices) {
    if (d.public_key.empty()) {
      // The founding row registered by `migrate` may carry no key file; on
      // its own machine the key is in the keyring anyway.
      if (!crypto::gpg_has_public_key(d.fingerprint)) {
        throw std::runtime_error(
            "device '" + d.name +
            "' has no stored public key and is not in the local keyring; "
            "cannot wrap to it");
      }
      continue;
    }
    const std::string fpr = crypto::gpg_import_public_key(d.public_key);
    if (fpr != db::normalize_fingerprint(d.fingerprint)) {
      throw std::runtime_error(
          "device '" + d.name +
          "': stored public key does not match its registered fingerprint "
          "(possible tampering) — refusing to encrypt to it");
    }
  }
}

RewrapStats rewrap_all_to_device(KeyStore& store, const db::Device& target,
                                 std::string_view my_fingerprint,
                                 const ProgressFn& progress) {
  RewrapStats st;
  const auto ids = store.all_entry_ids();
  const auto done = store.entry_ids_wrapped_for(target.id);  // sorted
  st.total = ids.size();
  std::size_t i = 0;
  for (const auto id : ids) {
    ++i;
    if (std::binary_search(done.begin(), done.end(), id)) {
      ++st.skipped;
      continue;
    }
    grant_one(store, my_fingerprint, id, target);
    ++st.wrapped;
    if (progress) progress(i, st.total, "entry " + std::to_string(id));
  }
  return st;
}

void grant_entry_to_device(KeyStore& store, std::string_view my_fingerprint,
                           std::int64_t id, const db::Device& target) {
  ensure_device_keys_local({target});  // import + pin before we encrypt to it
  grant_one(store, my_fingerprint, id, target);
}

void rotate_entry(KeyStore& store, std::string_view my_fingerprint,
                  std::int64_t id, std::vector<db::Device> recipients) {
  if (recipients.empty()) {
    throw std::runtime_error(
        "rotate_entry: refusing to leave entry " + std::to_string(id) +
        " with no readers");
  }
  sort_by_id(recipients);
  ensure_device_keys_local(recipients);
  rotate_one(store, my_fingerprint, id, recipients, nullptr);
}

RotateStats rotate_all(KeyStore& store, std::string_view my_fingerprint,
                       const ProgressFn& progress) {
  const auto active = store.active_devices();
  if (active.empty()) {
    throw std::runtime_error(
        "rotate: no active devices — refusing to rotate the vault into an "
        "unreadable state");
  }
  ensure_device_keys_local(active);
  std::map<std::int64_t, db::Device> active_by_id;
  for (const auto& d : active) active_by_id[d.id] = d;

  RotateStats st;
  const auto ids = store.all_entry_ids();
  st.total = ids.size();
  std::size_t i = 0;
  for (const auto id : ids) {
    ++i;
    // Preserve this entry's membership: rotate to its current active members,
    // NOT to all active devices (group encryption must survive a rotate). An
    // entry with no recorded members (pre-membership data) falls back to all
    // active, keeping a flat vault's behavior unchanged.
    std::vector<db::Device> recipients;
    for (std::int64_t did : store.device_ids_for_entry(id)) {
      if (auto it = active_by_id.find(did); it != active_by_id.end())
        recipients.push_back(it->second);
    }
    if (recipients.empty()) recipients = active;
    sort_by_id(recipients);

    bool was_v1 = false;
    rotate_one(store, my_fingerprint, id, recipients, &was_v1);
    ++st.rotated;
    if (was_v1) ++st.upgraded_v1;
    if (progress) progress(i, st.total, "entry " + std::to_string(id));
  }
  return st;
}

namespace {

struct EncryptedForAll {
  std::string blob;
  std::string legacy_wrap;
  std::vector<db::WrappedKey> wraps;
};

// Encrypt `plaintext` under a fresh K and wrap to a CHOSEN recipient set (+
// legacy). `recipients` must already be sorted by id. With an empty set this
// is byte-equivalent to today's single-wrap write (legacy = my_fingerprint).
EncryptedForAll encrypt_for_set(std::string_view my_fingerprint,
                                std::string_view plaintext,
                                const std::vector<db::Device>& recipients) {
  if (!recipients.empty()) ensure_device_keys_local(recipients);

  crypto::SecureBytes k(crypto::random_bytes(32));
  EncryptedForAll out;
  out.blob = crypto::serialize_v2(crypto::aes256_gcm_encrypt(plaintext, k.bytes()));
  std::string raw_key(reinterpret_cast<const char*>(k.bytes().data()),
                      k.bytes().size());
  try {
    out.wraps = wrap_to_set(raw_key, recipients, my_fingerprint, out.legacy_wrap);
  } catch (...) {
    OPENSSL_cleanse(raw_key.data(), raw_key.size());
    throw;
  }
  OPENSSL_cleanse(raw_key.data(), raw_key.size());
  return out;
}

}  // namespace

std::int64_t store_new_entry(KeyStore& store, std::string_view my_fingerprint,
                             std::string_view plaintext,
                             std::string_view note) {
  // Default recipients = every active device (active_devices() is id-sorted).
  EncryptedForAll enc =
      encrypt_for_set(my_fingerprint, plaintext, store.active_devices());
  return store.insert_entry_with_keys(enc.blob, enc.legacy_wrap, note, 2,
                                      enc.wraps);
}

std::int64_t store_new_entry_for(KeyStore& store, std::string_view my_fingerprint,
                                 std::string_view plaintext, std::string_view note,
                                 std::vector<db::Device> recipients) {
  sort_by_id(recipients);
  EncryptedForAll enc =
      encrypt_for_set(my_fingerprint, plaintext, recipients);
  return store.insert_entry_with_keys(enc.blob, enc.legacy_wrap, note, 2,
                                      enc.wraps);
}

void replace_entry_password(KeyStore& store, std::string_view my_fingerprint,
                            std::int64_t id, std::string_view plaintext) {
  // Keep the entry's CURRENT recipient set on a password change (don't silently
  // widen access); fall back to all active for pre-membership rows.
  std::vector<db::Device> recipients;
  {
    std::map<std::int64_t, db::Device> active_by_id;
    for (const auto& d : store.active_devices()) active_by_id[d.id] = d;
    for (std::int64_t did : store.device_ids_for_entry(id)) {
      if (auto it = active_by_id.find(did); it != active_by_id.end())
        recipients.push_back(it->second);
    }
    if (recipients.empty())
      for (auto& [unused, d] : active_by_id) recipients.push_back(d);
  }
  sort_by_id(recipients);
  EncryptedForAll enc =
      encrypt_for_set(my_fingerprint, plaintext, recipients);
  store.replace_entry_keys(id, enc.blob, enc.legacy_wrap, 2, enc.wraps);
}

}  // namespace pwmgr::sharing
