#include <string>
#include <vector>

#include <openssl/evp.h>

#include "crypto/aes.h"
#include "crypto/base64.h"
#include "test_framework.h"

using namespace pwmgr::crypto;

namespace {
// Produce a v1-format blob base64(IV(16) || AES-256-CBC ct) the same way the
// legacy writer did, so we can exercise the v1 read path without real data.
std::string cbc_encrypt_b64(std::string_view pt,
                            const std::vector<unsigned char>& key) {
  auto iv = random_bytes(16);
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
  return base64_encode(blob.data(), blob.size());
}
}  // namespace

TEST_CASE("v1 AES-256-CBC decrypt recovers plaintext") {
  auto key = random_bytes(32);
  for (std::string pt : {std::string("x"), std::string("hunter2"),
                         std::string(16, 'A'), std::string(100, 'Z')}) {
    std::string blob = cbc_encrypt_b64(pt, key);
    CHECK_EQ(aes256_cbc_decrypt(blob, key), pt);
  }
}

TEST_CASE("v2 AES-256-GCM roundtrip") {
  auto key = random_bytes(32);
  for (std::string pt : {std::string(""), std::string("p@ss"),
                         std::string(64, 'q')}) {
    std::string blob = aes256_gcm_encrypt(pt, key);
    CHECK_EQ(aes256_gcm_decrypt(blob, key), pt);
  }
}

TEST_CASE("v2 GCM detects tampering (the property CBC lacks)") {
  auto key = random_bytes(32);
  std::string blob = aes256_gcm_encrypt("secret", key);
  // Flip a character in the middle of the base64 ciphertext.
  std::string tampered = blob;
  tampered[tampered.size() / 2] =
      (tampered[tampered.size() / 2] == 'A') ? 'B' : 'A';
  CHECK_THROWS(aes256_gcm_decrypt(tampered, key));
}

TEST_CASE("v2 GCM rejects wrong key") {
  auto key = random_bytes(32);
  auto wrong = random_bytes(32);
  std::string blob = aes256_gcm_encrypt("secret", key);
  CHECK_THROWS(aes256_gcm_decrypt(blob, wrong));
}

TEST_CASE("non-32-byte key is rejected") {
  std::vector<unsigned char> shortkey(16, 0);
  CHECK_THROWS(aes256_gcm_encrypt("x", shortkey));
}
