#include "sharing/rewrap.h"

#include <algorithm>
#include <cstdio>
#include <stdexcept>

#include <openssl/crypto.h>

#include "crypto/aes.h"
#include "crypto/encryptor.h"
#include "crypto/envelope.h"
#include "crypto/gpg.h"
#include "crypto/secret.h"

namespace pwmgr::sharing {

namespace {

// D5: the legacy passwords.aes_key wrap targets the founding device while it
// is active, else the lowest-id active device. With no devices at all
// (pre-migration DB) the caller's own fingerprint keeps today's behavior.
std::string legacy_recipient(KeyStore& store,
                             const std::vector<db::Device>& active,
                             std::string_view my_fingerprint) {
  if (active.empty()) return std::string(my_fingerprint);
  auto founding = store.founding_device();
  if (founding && founding->status == "active") return founding->fingerprint;
  std::fprintf(stderr,
               "[INFO] founding device is not active; the legacy aes_key wrap "
               "now targets device '%s'\n",
               active.front().name.c_str());
  return active.front().fingerprint;  // active_devices() is ORDER BY id
}

// Wrap the raw 32-byte key to the legacy recipient and every active device.
// `legacy_out` receives the aes_key wrap; returns the per-device wraps.
std::vector<db::WrappedKey> wrap_to_all(const std::string& raw_key,
                                        const std::string& legacy_fpr,
                                        const std::vector<db::Device>& active,
                                        std::string& legacy_out) {
  legacy_out = crypto::gpg_encrypt_to_fingerprint(raw_key, legacy_fpr);
  std::vector<db::WrappedKey> wraps;
  wraps.reserve(active.size());
  for (const auto& d : active) {
    wraps.push_back(
        {d.id, crypto::gpg_encrypt_to_fingerprint(raw_key, d.fingerprint)});
  }
  return wraps;
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
    ++st.wrapped;
    if (progress) progress(i, st.total, "entry " + std::to_string(id));
  }
  return st;
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
  const std::string legacy_fpr =
      legacy_recipient(store, active, my_fingerprint);

  RotateStats st;
  const auto ids = store.all_entry_ids();
  st.total = ids.size();
  std::size_t i = 0;
  for (const auto id : ids) {
    ++i;
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
      wraps = wrap_to_all(raw_key, legacy_fpr, active, legacy_wrap);
    } catch (...) {
      OPENSSL_cleanse(raw_key.data(), raw_key.size());
      throw;
    }
    OPENSSL_cleanse(raw_key.data(), raw_key.size());

    store.replace_entry_keys(id, blob, legacy_wrap, 2, wraps);
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

EncryptedForAll encrypt_for_all(KeyStore& store, std::string_view my_fingerprint,
                                std::string_view plaintext) {
  const auto active = store.active_devices();
  if (!active.empty()) ensure_device_keys_local(active);
  const std::string legacy_fpr =
      legacy_recipient(store, active, my_fingerprint);
  if (legacy_fpr.empty()) {
    throw std::runtime_error("no recipient fingerprint available for encrypt");
  }

  crypto::SecureBytes k(crypto::random_bytes(32));
  EncryptedForAll out;
  out.blob = crypto::serialize_v2(crypto::aes256_gcm_encrypt(plaintext, k.bytes()));
  std::string raw_key(reinterpret_cast<const char*>(k.bytes().data()),
                      k.bytes().size());
  try {
    out.wraps = wrap_to_all(raw_key, legacy_fpr, active, out.legacy_wrap);
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
  EncryptedForAll enc = encrypt_for_all(store, my_fingerprint, plaintext);
  return store.insert_entry_with_keys(enc.blob, enc.legacy_wrap, note, 2,
                                      enc.wraps);
}

void replace_entry_password(KeyStore& store, std::string_view my_fingerprint,
                            std::int64_t id, std::string_view plaintext) {
  EncryptedForAll enc = encrypt_for_all(store, my_fingerprint, plaintext);
  store.replace_entry_keys(id, enc.blob, enc.legacy_wrap, 2, enc.wraps);
}

}  // namespace pwmgr::sharing
