// The multi-device lifecycle, end to end, with ZERO real secrets: ephemeral
// GPG keyrings (no passphrase) + the in-memory KeyStore. Proves enroll,
// resume, rotate-after-revoke (incl. v1 upgrade) and the write path — the
// same engines production wires to the real Repository.
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "crypto/aes.h"
#include "crypto/base64.h"
#include "crypto/encryptor.h"
#include "crypto/envelope.h"
#include "crypto/gpg.h"
#include "fake_keystore.h"
#include "gpg_test_home.h"
#include "sharing/rewrap.h"
#include "test_framework.h"

using namespace pwmgr;

namespace {

// v1-format blob base64(IV(16) || AES-256-CBC ct), as the legacy writer made
// them (same helper as test_aes.cpp).
std::string cbc_encrypt_b64(std::string_view pt,
                            const std::vector<unsigned char>& key) {
  auto iv = crypto::random_bytes(16);
  EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
  std::vector<unsigned char> out(pt.size() + 16);
  int l = 0, t = 0;
  EVP_EncryptUpdate(c, out.data(), &l,
                    reinterpret_cast<const unsigned char*>(pt.data()),
                    static_cast<int>(pt.size()));
  t = l;
  EVP_EncryptFinal_ex(c, out.data() + t, &l);
  t += l;
  EVP_CIPHER_CTX_free(c);
  std::vector<unsigned char> blob;
  blob.insert(blob.end(), iv.begin(), iv.end());
  blob.insert(blob.end(), out.begin(), out.begin() + t);
  return crypto::base64_encode(blob.data(), blob.size());
}

std::string decrypt_via(tf::InMemoryKeyStore& store, std::int64_t id,
                        const std::string& fpr) {
  auto e = store.get_entry(id);
  return crypto::Encryptor("").decrypt(e.password_blob,
                                       store.wrapped_key_for(id, fpr));
}

}  // namespace

TEST_CASE("enroll round-trip: B gains real access; resumable second run") {
  tf::EphemeralKeyring ring;
  const std::string fprA = ring.gen_key("deviceA");
  const std::string fprB = ring.gen_key("deviceB");

  tf::InMemoryKeyStore store;
  // Seed ONLY A active, then create entries — so B genuinely has no wraps
  // until the engine runs (with B already active, store_new_entry would wrap
  // to B at creation and the engine would skip everything).
  store.seed_device("deviceA", fprA, crypto::gpg_export_public_key(fprA));
  const std::vector<std::string> secrets = {"pt-one", "pt-two", "pt-three"};
  std::vector<std::int64_t> ids;
  for (std::size_t i = 0; i < secrets.size(); ++i) {
    ids.push_back(sharing::store_new_entry(store, fprA, secrets[i],
                                           "note" + std::to_string(i)));
  }
  // Now enroll B.
  std::int64_t devB =
      store.seed_device("deviceB", fprB, crypto::gpg_export_public_key(fprB));
  auto st = sharing::rewrap_all_to_device(store, store.devices[devB], fprA);
  CHECK_EQ(st.total, static_cast<std::size_t>(3));
  CHECK_EQ(st.wrapped, static_cast<std::size_t>(3));
  CHECK_EQ(st.skipped, static_cast<std::size_t>(0));
  for (std::size_t i = 0; i < ids.size(); ++i) {
    CHECK_EQ(decrypt_via(store, ids[i], fprB), secrets[i]);  // the core feature
    CHECK_EQ(decrypt_via(store, ids[i], fprA), secrets[i]);  // A unaffected
  }

  // Resume: second run does no work.
  auto st2 = sharing::rewrap_all_to_device(store, store.devices[devB], fprA);
  CHECK_EQ(st2.wrapped, static_cast<std::size_t>(0));
  CHECK_EQ(st2.skipped, static_cast<std::size_t>(3));
  CHECK_EQ(store.wrap_count_for(devB), static_cast<std::size_t>(3));
}

TEST_CASE("rotate: revoked device loses access; v1 upgrades to v2; legacy refreshed") {
  tf::EphemeralKeyring ring;
  const std::string fprA = ring.gen_key("deviceA");
  const std::string fprB = ring.gen_key("deviceB");

  tf::InMemoryKeyStore store;
  std::int64_t devA =
      store.seed_device("deviceA", fprA, crypto::gpg_export_public_key(fprA));
  std::int64_t devB =
      store.seed_device("deviceB", fprB, crypto::gpg_export_public_key(fprB));

  // entry1: fabricated v1 row (CBC blob; legacy wrap = GPG(K -> A)); also
  // wrapped to B, as a backfilled+enrolled vault would be.
  auto k1 = crypto::random_bytes(32);
  std::string k1s(reinterpret_cast<const char*>(k1.data()), k1.size());
  {
    pwmgr::db::Entry e;
    e.id = store.next_entry_id++;
    e.password_blob = cbc_encrypt_b64("legacy-secret", k1);
    e.note = "legacy";
    e.aes_key_armored = crypto::gpg_encrypt_to_fingerprint(k1s, fprA);
    e.enc_version = 1;
    store.entries[e.id] = e;
    store.wraps[{e.id, devA}] = e.aes_key_armored;
    store.wraps[{e.id, devB}] = crypto::gpg_encrypt_to_fingerprint(k1s, fprB);
  }
  // entry2: normal v2 entry created while both devices were active.
  std::int64_t id2 = sharing::store_new_entry(store, fprA, "modern-secret", "v2");
  CHECK_EQ(decrypt_via(store, 1, fprB), std::string("legacy-secret"));
  CHECK_EQ(decrypt_via(store, id2, fprB), std::string("modern-secret"));

  // Revoke B (status + wrap deletion, as Repository::revoke_device does).
  store.devices[devB].status = "revoked";
  for (auto it = store.wraps.begin(); it != store.wraps.end();)
    it = (it->first.second == devB) ? store.wraps.erase(it) : std::next(it);

  auto st = sharing::rotate_all(store, fprA);
  CHECK_EQ(st.total, static_cast<std::size_t>(2));
  CHECK_EQ(st.rotated, static_cast<std::size_t>(2));
  CHECK_EQ(st.upgraded_v1, static_cast<std::size_t>(1));

  // Every blob is now v2; A still decrypts everything.
  for (std::int64_t id : {static_cast<std::int64_t>(1), id2}) {
    auto e = store.get_entry(id);
    CHECK_EQ(e.password_blob.substr(0, 3), std::string("v2:"));
    CHECK_EQ(e.enc_version, 2);
  }
  CHECK_EQ(decrypt_via(store, 1, fprA), std::string("legacy-secret"));
  CHECK_EQ(decrypt_via(store, id2, fprA), std::string("modern-secret"));

  // B has no wraps left, and the OLD key no longer opens the new blob:
  // parse first and assert v2 so the failure is the GCM tag (a raw "v2:"
  // string would already fail on base64, masking a wrong-key regression).
  CHECK_EQ(store.wrap_count_for(devB), static_cast<std::size_t>(0));
  auto parsed = crypto::parse_password_blob(store.get_entry(1).password_blob);
  REQUIRE(parsed.version == crypto::Version::V2_Gcm);
  CHECK_THROWS(crypto::aes256_gcm_decrypt(parsed.payload, k1));

  // D5: the legacy aes_key was refreshed and still decrypts for A (founding).
  auto e1 = store.get_entry(1);
  CHECK_EQ(crypto::Encryptor("").decrypt(e1.password_blob, e1.aes_key_armored),
           std::string("legacy-secret"));
}

TEST_CASE("rotate refuses with zero active devices") {
  tf::EphemeralKeyring ring;
  const std::string fprA = ring.gen_key("deviceA");
  tf::InMemoryKeyStore store;
  std::int64_t devA = store.seed_device("deviceA", fprA, "", "revoked");
  (void)devA;
  sharing::store_new_entry(store, fprA, "s", "n");  // no devices active: legacy-only
  CHECK_THROWS(sharing::rotate_all(store, fprA));
}

TEST_CASE("write path wraps to all active devices + legacy aes_key") {
  tf::EphemeralKeyring ring;
  const std::string fprA = ring.gen_key("deviceA");
  const std::string fprB = ring.gen_key("deviceB");

  tf::InMemoryKeyStore store;
  std::int64_t devA =
      store.seed_device("deviceA", fprA, crypto::gpg_export_public_key(fprA));
  std::int64_t devB =
      store.seed_device("deviceB", fprB, crypto::gpg_export_public_key(fprB));

  std::int64_t id = sharing::store_new_entry(store, fprA, "shared-pt", "note");
  CHECK_EQ(store.wrap_count_for(devA), static_cast<std::size_t>(1));
  CHECK_EQ(store.wrap_count_for(devB), static_cast<std::size_t>(1));
  CHECK_EQ(decrypt_via(store, id, fprA), std::string("shared-pt"));
  CHECK_EQ(decrypt_via(store, id, fprB), std::string("shared-pt"));
  // Legacy aes_key (D5) present and decryptable (founding = A).
  auto e = store.get_entry(id);
  CHECK_EQ(crypto::Encryptor("").decrypt(e.password_blob, e.aes_key_armored),
           std::string("shared-pt"));
  // Unknown fingerprint falls back to the legacy wrap (decryptable here only
  // because A's key is in this test keyring — the fallback is by design).
  CHECK_EQ(store.wrapped_key_for(id, std::string(40, 'A')), e.aes_key_armored);

  // replace_entry_password keeps the full wrap set.
  sharing::replace_entry_password(store, fprA, id, "new-pt");
  CHECK_EQ(decrypt_via(store, id, fprA), std::string("new-pt"));
  CHECK_EQ(decrypt_via(store, id, fprB), std::string("new-pt"));
}

// ---- group encryption (per-entry recipient sets) ----
// NOTE: one shared test keyring holds every device's secret, so we assert on
// the access MATRIX (who holds a wrap) rather than on decrypt-failure for an
// excluded device — crypto-level exclusion is guaranteed by GPG and covered by
// the existing rotate test. This mirrors the fallback note in the write-path
// test above.

TEST_CASE("subset create: entry encrypted to a chosen device set only") {
  tf::EphemeralKeyring ring;
  const std::string fprA = ring.gen_key("deviceA");
  const std::string fprB = ring.gen_key("deviceB");
  const std::string fprC = ring.gen_key("deviceC");
  tf::InMemoryKeyStore store;
  auto a = store.seed_device("deviceA", fprA, crypto::gpg_export_public_key(fprA));
  auto b = store.seed_device("deviceB", fprB, crypto::gpg_export_public_key(fprB));
  auto c = store.seed_device("deviceC", fprC, crypto::gpg_export_public_key(fprC));

  std::int64_t id = sharing::store_new_entry_for(
      store, fprA, "group-secret", "shared",
      {store.devices[a], store.devices[b]});  // exclude C
  CHECK_EQ(store.wrap_count_for(a), static_cast<std::size_t>(1));
  CHECK_EQ(store.wrap_count_for(b), static_cast<std::size_t>(1));
  CHECK_EQ(store.wrap_count_for(c), static_cast<std::size_t>(0));  // C excluded
  auto m = store.device_ids_for_entry(id);
  REQUIRE(m.size() == static_cast<std::size_t>(2));
  CHECK_EQ(m[0], a);
  CHECK_EQ(m[1], b);
  CHECK_EQ(decrypt_via(store, id, fprA), std::string("group-secret"));
  CHECK_EQ(decrypt_via(store, id, fprB), std::string("group-secret"));
}

TEST_CASE("group encryption can exclude the founding device (no backdoor)") {
  tf::EphemeralKeyring ring;
  const std::string fprA = ring.gen_key("deviceA");  // founding (lowest id)
  const std::string fprB = ring.gen_key("deviceB");
  const std::string fprC = ring.gen_key("deviceC");
  tf::InMemoryKeyStore store;
  auto a = store.seed_device("deviceA", fprA, crypto::gpg_export_public_key(fprA));
  auto b = store.seed_device("deviceB", fprB, crypto::gpg_export_public_key(fprB));
  auto c = store.seed_device("deviceC", fprC, crypto::gpg_export_public_key(fprC));

  std::int64_t id = sharing::store_new_entry_for(
      store, fprA, "for-b-and-c-only", "secret",
      {store.devices[b], store.devices[c]});  // exclude founding A
  // Founding A holds NO wrap row: it is not in the recipient set. The legacy
  // aes_key targets the lowest-id MEMBER (B), so the fallback is not a wrap to
  // A — A genuinely cannot read it.
  CHECK_EQ(store.wrap_count_for(a), static_cast<std::size_t>(0));
  auto m = store.device_ids_for_entry(id);
  REQUIRE(m.size() == static_cast<std::size_t>(2));
  CHECK_EQ(m[0], b);
  CHECK_EQ(m[1], c);
}

TEST_CASE("entry grant: one device gains access to a single entry") {
  tf::EphemeralKeyring ring;
  const std::string fprA = ring.gen_key("deviceA");
  const std::string fprB = ring.gen_key("deviceB");
  tf::InMemoryKeyStore store;
  auto a = store.seed_device("deviceA", fprA, crypto::gpg_export_public_key(fprA));
  auto b = store.seed_device("deviceB", fprB, crypto::gpg_export_public_key(fprB));

  // Two entries shared with A only.
  std::int64_t id1 = sharing::store_new_entry_for(store, fprA, "s1", "n1",
                                                  {store.devices[a]});
  std::int64_t id2 = sharing::store_new_entry_for(store, fprA, "s2", "n2",
                                                  {store.devices[a]});
  CHECK_EQ(store.wrap_count_for(b), static_cast<std::size_t>(0));

  sharing::grant_entry_to_device(store, fprA, id1, store.devices[b]);
  // B reads id1; the grant is per-entry, so id2 still excludes B.
  CHECK_EQ(decrypt_via(store, id1, fprB), std::string("s1"));
  CHECK_EQ(store.device_ids_for_entry(id1).size(), static_cast<std::size_t>(2));
  auto m2 = store.device_ids_for_entry(id2);
  REQUIRE(m2.size() == static_cast<std::size_t>(1));
  CHECK_EQ(m2[0], a);
}

TEST_CASE("entry revoke rotates that entry and drops the device") {
  tf::EphemeralKeyring ring;
  const std::string fprA = ring.gen_key("deviceA");
  const std::string fprB = ring.gen_key("deviceB");
  tf::InMemoryKeyStore store;
  auto a = store.seed_device("deviceA", fprA, crypto::gpg_export_public_key(fprA));
  auto b = store.seed_device("deviceB", fprB, crypto::gpg_export_public_key(fprB));

  std::int64_t id = sharing::store_new_entry_for(
      store, fprA, "shared-secret", "n", {store.devices[a], store.devices[b]});
  const std::string old_blob = store.get_entry(id).password_blob;
  const std::string b_wrap_before = store.wraps[{id, b}];  // B's current wrap

  // Remove B: rotate the entry to {A}.
  sharing::rotate_entry(store, fprA, id, {store.devices[a]});
  CHECK_EQ(store.wrap_count_for(b), static_cast<std::size_t>(0));  // B dropped
  auto m = store.device_ids_for_entry(id);
  REQUIRE(m.size() == static_cast<std::size_t>(1));
  CHECK_EQ(m[0], a);
  CHECK_EQ(decrypt_via(store, id, fprA), std::string("shared-secret"));

  // Real revoke: fresh K. The blob changed, and B's OLD key cannot open it.
  const std::string new_blob = store.get_entry(id).password_blob;
  CHECK(new_blob != old_blob);
  std::string old_k = crypto::gpg_decrypt(b_wrap_before);  // 32 bytes (ring has B)
  auto parsed = crypto::parse_password_blob(new_blob);
  REQUIRE(parsed.version == crypto::Version::V2_Gcm);
  std::vector<unsigned char> kv(old_k.begin(), old_k.end());
  CHECK_THROWS(crypto::aes256_gcm_decrypt(parsed.payload, kv));

  // Removing the last reader is refused (would orphan the entry).
  CHECK_THROWS(sharing::rotate_entry(store, fprA, id, {}));
}

TEST_CASE("rotate_all preserves per-entry membership (no grant-all)") {
  tf::EphemeralKeyring ring;
  const std::string fprA = ring.gen_key("deviceA");
  const std::string fprB = ring.gen_key("deviceB");
  const std::string fprC = ring.gen_key("deviceC");
  tf::InMemoryKeyStore store;
  auto a = store.seed_device("deviceA", fprA, crypto::gpg_export_public_key(fprA));
  auto b = store.seed_device("deviceB", fprB, crypto::gpg_export_public_key(fprB));
  auto c = store.seed_device("deviceC", fprC, crypto::gpg_export_public_key(fprC));

  std::int64_t id1 = sharing::store_new_entry_for(
      store, fprA, "g1", "n1", {store.devices[a], store.devices[b]});  // not C
  std::int64_t id2 = sharing::store_new_entry(store, fprA, "g2", "n2");  // all 3

  sharing::rotate_all(store, fprA);

  // id1 still excludes C; id2 still has all three. A global rotate must not
  // widen any entry's recipient set.
  auto m1 = store.device_ids_for_entry(id1);
  CHECK_EQ(m1.size(), static_cast<std::size_t>(2));
  CHECK(std::find(m1.begin(), m1.end(), c) == m1.end());
  CHECK_EQ(store.device_ids_for_entry(id2).size(), static_cast<std::size_t>(3));
  CHECK_EQ(decrypt_via(store, id1, fprA), std::string("g1"));
  CHECK_EQ(decrypt_via(store, id2, fprC), std::string("g2"));
}

TEST_CASE("ensure_device_keys_local pins stored keys against fingerprints") {
  tf::EphemeralKeyring ring;
  const std::string fprA = ring.gen_key("deviceA");
  const std::string fprB = ring.gen_key("deviceB");
  const std::string exportA = crypto::gpg_export_public_key(fprA);

  // Honest device: passes.
  sharing::ensure_device_keys_local(
      {pwmgr::db::Device{1, "a", fprA, exportA, "active", ""}});
  // Tampered: B's fingerprint registered but A's key stored.
  CHECK_THROWS(sharing::ensure_device_keys_local(
      {pwmgr::db::Device{2, "b", fprB, exportA, "active", ""}}));
  // No stored key but present in keyring (the founding device on its own
  // machine): passes. Absent from keyring: throws.
  sharing::ensure_device_keys_local(
      {pwmgr::db::Device{3, "c", fprA, "", "active", ""}});
  CHECK_THROWS(sharing::ensure_device_keys_local(
      {pwmgr::db::Device{4, "d", std::string(40, 'B'), "", "active", ""}}));
}
