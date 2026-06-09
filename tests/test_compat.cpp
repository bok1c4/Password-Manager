// BACKWARD-COMPAT REGRESSION (gated): decrypts a REAL captured v1 row end-to-end
// (GPG-unwrap the armored AES key -> AES-256-CBC) and asserts non-empty
// plaintext. This is the gate for the hard invariant that the existing rows stay
// readable. Requires the GPG secret key (passphrase via pinentry) and the
// captured fixtures, so it only runs with --gated:
//   PWMGR_COMPAT_PASSWORD=/home/user/pwmgr-backups/compat_id1_password.b64
//   PWMGR_COMPAT_AESKEY=/home/user/pwmgr-backups/compat_id1_aeskey.asc
//   build/make/pwmgr_tests --gated
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include "crypto/encryptor.h"
#include "test_framework.h"

using namespace pwmgr::crypto;

namespace {
std::string read_file(const std::string& path) {
  std::ifstream f(path);
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}
std::string rstrip(std::string s) {
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
  return s;
}
}  // namespace

TEST_CASE_GATED("backward-compat: a real v1 row decrypts to non-empty plaintext") {
  const char* pw_path = std::getenv("PWMGR_COMPAT_PASSWORD");
  const char* ak_path = std::getenv("PWMGR_COMPAT_AESKEY");
  REQUIRE(pw_path != nullptr);
  REQUIRE(ak_path != nullptr);

  std::string blob = rstrip(read_file(pw_path));    // bare base64 (v1)
  std::string aeskey = read_file(ak_path);          // GPG armored, keep as-is
  REQUIRE(!blob.empty());
  REQUIRE(!aeskey.empty());

  // Recipient fingerprint is unused on the decrypt path.
  Encryptor enc("");
  std::string plaintext = enc.decrypt(blob, aeskey);
  CHECK(!plaintext.empty());  // a thrown error or empty would fail the invariant

  // If the known plaintext is supplied, assert byte-equality (strongest gate).
  if (const char* expected = std::getenv("PWMGR_COMPAT_EXPECTED")) {
    CHECK_EQ(plaintext, std::string(expected));
  }
}
