// GPG import/export + swapped-key detection, against EPHEMERAL keyrings only
// (no real secrets, no gating). The enroll/rotate engine tests live in
// test_rewrap.cpp; this file covers the key-handling primitives.
#include <string>

#include "crypto/gpg.h"
#include "db/device.h"
#include "gpg_test_home.h"
#include "test_framework.h"

using namespace pwmgr;

TEST_CASE("gpg: import returns the imported fingerprint; idempotent; garbage throws") {
  std::string exported, fprA;
  {
    tf::EphemeralKeyring ring1;
    fprA = ring1.gen_key("deviceA");
    exported = crypto::gpg_export_public_key(fprA);
    CHECK(!exported.empty());
    CHECK(exported.find("PUBLIC KEY BLOCK") != std::string::npos);
  }
  {
    tf::EphemeralKeyring ring2;  // fresh keyring: A is unknown here
    CHECK(!crypto::gpg_has_public_key(fprA));
    CHECK_EQ(crypto::gpg_inspect_public_key(exported), fprA);
    CHECK(!crypto::gpg_has_public_key(fprA));  // inspection wrote nothing
    CHECK_EQ(crypto::gpg_import_public_key(exported), fprA);
    CHECK(crypto::gpg_has_public_key(fprA));
    // Re-import is idempotent.
    CHECK_EQ(crypto::gpg_import_public_key(exported), fprA);
    CHECK_THROWS(crypto::gpg_import_public_key("not a key at all"));
    CHECK_THROWS(crypto::gpg_export_public_key(
        "0000000000000000000000000000000000000000"));
  }
}

TEST_CASE("gpg: secret-key material is rejected with no keyring write") {
  std::string secret_export, fprA;
  {
    tf::EphemeralKeyring ring1;
    fprA = ring1.gen_key("deviceA");
    // Export the SECRET key (no-protection test key; this is the accident
    // the import path must catch).
    FILE* p = ::popen(("gpg --batch --export-secret-keys --armor " + fprA +
                       " 2>/dev/null")
                          .c_str(),
                      "r");
    REQUIRE(p != nullptr);
    char buf[4096];
    std::size_t n;
    while ((n = ::fread(buf, 1, sizeof(buf), p)) > 0) secret_export.append(buf, n);
    ::pclose(p);
    REQUIRE(secret_export.find("PRIVATE KEY BLOCK") != std::string::npos);
  }
  tf::EphemeralKeyring ring2;
  CHECK_THROWS(crypto::gpg_inspect_public_key(secret_export));
  CHECK_THROWS(crypto::gpg_import_public_key(secret_export));
  CHECK(!crypto::gpg_has_public_key(fprA));  // nothing was written
  CHECK(!crypto::gpg_has_secret_key(fprA));
}

TEST_CASE("gpg: swapped key file detected (the device-add comparison)") {
  tf::EphemeralKeyring ring;
  std::string fprA = ring.gen_key("deviceA");
  std::string fprB = ring.gen_key("deviceB");
  REQUIRE(fprA != fprB);
  std::string exportA = crypto::gpg_export_public_key(fprA);
  // The exact cmd_device_add check: inspected fingerprint vs expected.
  CHECK(crypto::gpg_inspect_public_key(exportA) != fprB);
  CHECK_EQ(crypto::gpg_inspect_public_key(exportA), fprA);
  // Fingerprints from gpg are already canonical for normalize_fingerprint.
  CHECK_EQ(pwmgr::db::normalize_fingerprint(fprA), fprA);
}
