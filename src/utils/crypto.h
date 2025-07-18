#pragma once

#include "config/config_manager.h"
#include <optional>
#include <string>
#include <vector>

struct EncryptedPasswordsBeta {
  std::string encryptedPasswords;
};

class Encryptor {
public:
  static void printPublicKeyInfo(const std::string &pubKeyPath);
  static std::string
  printPublicKeyInfoAndReturnContent(const std::string &pubKeyPath);

  static std::optional<std::string>
  match_username_from_public_keys(const std::string &privKeyPath,
                                  const std::vector<KeyReference> &publicKeys);

  static EncryptedPasswordsBeta
  encrypt_passwords_with_pks(const std::string &passwords,
                             const std::vector<KeyReference> &publicKeys);

  static std::string decrypt_password(const std::string &encryptedData);
};
