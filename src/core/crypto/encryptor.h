#pragma once
#include <string>
#include <string_view>

namespace pwmgr::crypto {

struct NewEntry {
  std::string password_blob;     // "v2:"||base64(nonce||ct||tag) -> passwords.password
  std::string aes_key_armored;   // GPG-armored 32-byte AES key  -> passwords.aes_key
};

// Hybrid encrypt/decrypt facade. The 32-byte AES key is freshly generated per
// write and GPG-wrapped to the configured recipient fingerprint (identical to
// the legacy scheme). New writes use AES-256-GCM (v2); reads transparently
// handle both the legacy CBC (v1) rows and v2 rows.
class Encryptor {
 public:
  explicit Encryptor(std::string recipient_fingerprint);

  NewEntry encrypt(std::string_view plaintext) const;

  // Decrypts a stored entry (v1 or v2) given the password blob and the
  // GPG-armored AES key. Throws std::runtime_error on failure.
  std::string decrypt(std::string_view password_blob,
                      std::string_view aes_key_armored) const;

  const std::string& recipient_fingerprint() const { return recipient_fpr_; }

 private:
  std::string recipient_fpr_;
};

}  // namespace pwmgr::crypto
