#pragma once

#include <string>

class Encryptor {
public:
  static void printPublicKeyInfo(const std::string &pubKeyPath);
  static std::string
  printPublicKeyInfoAndReturnContent(const std::string &pubKeyPath);
};
