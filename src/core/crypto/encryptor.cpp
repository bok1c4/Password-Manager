#include "crypto/encryptor.h"

#include <stdexcept>

#include <openssl/crypto.h>

#include "crypto/aes.h"
#include "crypto/envelope.h"
#include "crypto/gpg.h"
#include "crypto/secret.h"

namespace pwmgr::crypto {

Encryptor::Encryptor(std::string recipient_fingerprint)
    : recipient_fpr_(std::move(recipient_fingerprint)) {}

NewEntry Encryptor::encrypt(std::string_view plaintext) const {
  if (recipient_fpr_.empty()) {
    throw std::runtime_error("No recipient fingerprint configured for encrypt");
  }

  SecureBytes key(random_bytes(32));
  std::string payload = aes256_gcm_encrypt(plaintext, key.bytes());

  // Wrap the raw 32-byte AES key with GPG, exactly as the legacy scheme does.
  std::string aes_key_str(reinterpret_cast<const char*>(key.bytes().data()),
                          key.bytes().size());
  std::string armored = gpg_encrypt_to_fingerprint(aes_key_str, recipient_fpr_);
  OPENSSL_cleanse(aes_key_str.data(), aes_key_str.size());  // wipe key copy

  return NewEntry{serialize_v2(payload), armored};
}

std::string Encryptor::decrypt(std::string_view password_blob,
                               std::string_view aes_key_armored) const {
  // Unwrap the AES key (GPG; may prompt for passphrase via pinentry).
  std::string raw_key = gpg_decrypt(aes_key_armored);
  SecureBytes key(std::vector<unsigned char>(raw_key.begin(), raw_key.end()));
  OPENSSL_cleanse(raw_key.data(), raw_key.size());  // wipe before any throw
  if (key.size() != 32) {
    throw std::runtime_error("Unwrapped AES key is not 32 bytes");
  }

  ParsedBlob parsed = parse_password_blob(password_blob);
  switch (parsed.version) {
    case Version::V1_Cbc:
      return aes256_cbc_decrypt(parsed.payload, key.bytes());
    case Version::V2_Gcm:
      return aes256_gcm_decrypt(parsed.payload, key.bytes());
  }
  throw std::runtime_error("Unknown envelope version");
}

}  // namespace pwmgr::crypto
