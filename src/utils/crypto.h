#pragma once

#include "config/config_manager.h"
#include <cstring>
#include <gpgme.h>
#include <openssl/rand.h>
#include <optional>
#include <string>
#include <vector>

struct EncryptedPasswordsBeta {
  std::string encryptedPasswords;
};

class Encryptor {
public:
  Encryptor(AppConfig *config);

  static bool import_private_key(const std::string &privateKeyPath);
  static bool load_private_key_for_decryption(const std::string &privKeyPath);

  static std::optional<gpgme_ctx_t>
  load_gpgme_ctx_with_privkey(const std::string &privKeyPath);

  static void printPublicKeyInfo(const std::string &pubKeyPath);
  static std::string
  printPublicKeyInfoAndReturnContent(const std::string &pubKeyPath);

  static std::optional<std::string>
  match_username_from_public_keys(const std::string &privKeyPath,
                                  const std::vector<KeyReference> &publicKeys);

  static EncryptedPasswordsBeta
  encrypt_passwords_with_pks(const std::string &passwords,
                             const std::vector<KeyReference> &publicKeys);

  static std::string decrypt_password(const std::string &encryptedData,
                                      gpgme_ctx_t ctx);

  static std::string generate_aes_key();

  static std::string aes_encrypt_password(const std::string &password,
                                          const std::string &aes_key);

  static std::string
  aes_decrypt_password(const std::string &encrypted_base64,
                       const std::vector<unsigned char> &aes_key);

  std::string decrypt_hybrid(const std::string &encryptedPassword,
                             const std::string &encryptedAesKey);

  static std::string base64_encode(const unsigned char *buffer, size_t length);

  static std::string get_fingerprint_from_pubkey(const std::string &pubKeyPath);

private:
  AppConfig *config_;
};
