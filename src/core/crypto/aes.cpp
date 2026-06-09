#include "crypto/aes.h"

#include <cstring>
#include <stdexcept>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "crypto/base64.h"

namespace pwmgr::crypto {

namespace {
constexpr int kGcmNonceLen = 12;
constexpr int kGcmTagLen = 16;
constexpr int kCbcIvLen = 16;

struct CipherCtx {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  CipherCtx() {
    if (!ctx) throw std::runtime_error("Failed to create EVP cipher context");
  }
  ~CipherCtx() {
    if (ctx) EVP_CIPHER_CTX_free(ctx);
  }
  operator EVP_CIPHER_CTX*() { return ctx; }
};
}  // namespace

std::vector<unsigned char> random_bytes(std::size_t n) {
  std::vector<unsigned char> out(n);
  if (RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
    throw std::runtime_error("Failed to obtain random bytes");
  }
  return out;
}

// ---- v1 legacy (byte-identical to the original aes_decrypt_password) ----
std::string aes256_cbc_decrypt(std::string_view base64_iv_ciphertext,
                               const std::vector<unsigned char>& key32) {
  if (key32.size() != 32) {
    throw std::runtime_error("AES key must be 32 bytes for AES-256");
  }

  std::vector<unsigned char> decoded = base64_decode(base64_iv_ciphertext);
  if (decoded.size() <= static_cast<std::size_t>(kCbcIvLen)) {
    throw std::runtime_error(
        "Decoded data too short to contain IV and ciphertext.");
  }

  unsigned char iv[kCbcIvLen];
  std::memcpy(iv, decoded.data(), kCbcIvLen);

  const unsigned char* ciphertext = decoded.data() + kCbcIvLen;
  const int ciphertext_len = static_cast<int>(decoded.size()) - kCbcIvLen;

  CipherCtx ctx;
  std::vector<unsigned char> plaintext(static_cast<std::size_t>(ciphertext_len) +
                                       16);
  int outlen = 0;
  int total = 0;

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key32.data(), iv) != 1)
    throw std::runtime_error("EVP_DecryptInit_ex failed");
  if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext,
                        ciphertext_len) != 1)
    throw std::runtime_error("EVP_DecryptUpdate failed");
  total = outlen;
  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen) != 1)
    throw std::runtime_error("EVP_DecryptFinal_ex failed");
  total += outlen;

  std::string result(reinterpret_cast<char*>(plaintext.data()),
                     static_cast<std::size_t>(total));
  OPENSSL_cleanse(plaintext.data(), plaintext.size());  // wipe recovered bytes
  return result;
}

// ---- v2 authenticated (AES-256-GCM) ----
std::string aes256_gcm_encrypt(std::string_view plaintext,
                               const std::vector<unsigned char>& key32) {
  if (key32.size() != 32) {
    throw std::runtime_error("AES key must be 32 bytes for AES-256");
  }

  std::vector<unsigned char> nonce = random_bytes(kGcmNonceLen);

  CipherCtx ctx;
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    throw std::runtime_error("GCM EncryptInit (cipher) failed");
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kGcmNonceLen, nullptr) !=
      1)
    throw std::runtime_error("GCM set IV length failed");
  if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce.data()) != 1)
    throw std::runtime_error("GCM EncryptInit (key/iv) failed");

  std::vector<unsigned char> ciphertext(plaintext.size());
  int outlen = 0;
  int ct_len = 0;
  if (EVP_EncryptUpdate(
          ctx, ciphertext.data(), &outlen,
          reinterpret_cast<const unsigned char*>(plaintext.data()),
          static_cast<int>(plaintext.size())) != 1)
    throw std::runtime_error("GCM EncryptUpdate failed");
  ct_len = outlen;
  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ct_len, &outlen) != 1)
    throw std::runtime_error("GCM EncryptFinal failed");
  ct_len += outlen;

  unsigned char tag[kGcmTagLen];
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kGcmTagLen, tag) != 1)
    throw std::runtime_error("GCM get tag failed");

  // Layout: nonce(12) || ciphertext || tag(16)
  std::vector<unsigned char> out;
  out.reserve(static_cast<std::size_t>(kGcmNonceLen) + ct_len + kGcmTagLen);
  out.insert(out.end(), nonce.begin(), nonce.end());
  out.insert(out.end(), ciphertext.begin(),
             ciphertext.begin() + ct_len);
  out.insert(out.end(), tag, tag + kGcmTagLen);

  return base64_encode(out.data(), out.size());
}

std::string aes256_gcm_decrypt(std::string_view base64_nonce_ct_tag,
                               const std::vector<unsigned char>& key32) {
  if (key32.size() != 32) {
    throw std::runtime_error("AES key must be 32 bytes for AES-256");
  }

  std::vector<unsigned char> decoded = base64_decode(base64_nonce_ct_tag);
  if (decoded.size() <
      static_cast<std::size_t>(kGcmNonceLen + kGcmTagLen)) {
    throw std::runtime_error("GCM blob too short for nonce + tag");
  }

  const unsigned char* nonce = decoded.data();
  const unsigned char* ciphertext = decoded.data() + kGcmNonceLen;
  const int ct_len =
      static_cast<int>(decoded.size()) - kGcmNonceLen - kGcmTagLen;
  unsigned char* tag = decoded.data() + kGcmNonceLen + ct_len;

  CipherCtx ctx;
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    throw std::runtime_error("GCM DecryptInit (cipher) failed");
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kGcmNonceLen, nullptr) !=
      1)
    throw std::runtime_error("GCM set IV length failed");
  if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce) != 1)
    throw std::runtime_error("GCM DecryptInit (key/iv) failed");

  std::vector<unsigned char> plaintext(static_cast<std::size_t>(ct_len) + 16);
  int outlen = 0;
  int total = 0;
  if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext, ct_len) != 1)
    throw std::runtime_error("GCM DecryptUpdate failed");
  total = outlen;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kGcmTagLen, tag) != 1)
    throw std::runtime_error("GCM set tag failed");

  // Returns 0 if the tag does not verify -> tampered/wrong key.
  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &outlen) != 1)
    throw std::runtime_error("GCM authentication failed (tag mismatch)");
  total += outlen;

  std::string result(reinterpret_cast<char*>(plaintext.data()),
                     static_cast<std::size_t>(total));
  OPENSSL_cleanse(plaintext.data(), plaintext.size());  // wipe recovered bytes
  return result;
}

}  // namespace pwmgr::crypto
