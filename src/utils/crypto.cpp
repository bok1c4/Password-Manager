#include "../utils/crypto.h"
#include <fstream>
#include <gpgme.h>
#include <iostream>
#include <sstream>

void Encryptor::printPublicKeyInfo(const std::string &pubKeyPath) {
  gpgme_check_version(nullptr);
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_error_t err;

  if (gpgme_new(&ctx) != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to initialize GPGME context.\n";
    return;
  }

  gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_LOCAL);

  std::ifstream in(pubKeyPath);
  if (!in) {
    std::cerr << "[ERROR] Could not open the public key file at: " << pubKeyPath
              << "\n";
    gpgme_release(ctx);
    return;
  }

  std::stringstream buffer;
  buffer << in.rdbuf();
  std::string keyData = buffer.str();

  gpgme_data_t keyDataObj;
  err =
      gpgme_data_new_from_mem(&keyDataObj, keyData.c_str(), keyData.size(), 0);
  if (err) {
    std::cerr << "[ERROR] Failed to create data buffer: " << gpgme_strerror(err)
              << "\n";
    gpgme_release(ctx);
    return;
  }

  err = gpgme_op_import(ctx, keyDataObj);
  if (err) {
    std::cerr << "[ERROR] Failed to import key: " << gpgme_strerror(err)
              << "\n";
    gpgme_data_release(keyDataObj);
    gpgme_release(ctx);
    return;
  }

  std::cout << "[INFO] Public key imported into GPG context (not persisted).\n";

  err = gpgme_op_keylist_start(ctx, nullptr, 0);
  if (err) {
    std::cerr << "[ERROR] Failed to start key listing.\n";
    gpgme_data_release(keyDataObj);
    gpgme_release(ctx);
    return;
  }

  while ((err = gpgme_op_keylist_next(ctx, &key)) == 0) {
    std::cout << "+----------------------------------+\n";
    std::cout << "| Key Fingerprint: " << key->subkeys->fpr << "\n";
    if (key->uids) {
      std::cout << "| User ID: " << key->uids->uid << "\n";
    }
    std::cout << "+----------------------------------+\n";
    gpgme_key_unref(key);
  }

  gpgme_op_keylist_end(ctx);
  gpgme_data_release(keyDataObj);
  gpgme_release(ctx);
}

std::string
Encryptor::printPublicKeyInfoAndReturnContent(const std::string &pubKeyPath) {
  gpgme_check_version(nullptr);
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_error_t err;

  if (gpgme_new(&ctx) != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to initialize GPGME context.\n";
    return "";
  }

  gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_LOCAL);

  std::ifstream in(pubKeyPath);
  if (!in) {
    std::cerr << "[ERROR] Could not open the public key file at: " << pubKeyPath
              << "\n";
    gpgme_release(ctx);
    return "";
  }

  std::stringstream buffer;
  buffer << in.rdbuf();
  std::string keyData = buffer.str(); // ✅ This is what you'll return

  gpgme_data_t keyDataObj;
  err =
      gpgme_data_new_from_mem(&keyDataObj, keyData.c_str(), keyData.size(), 0);
  if (err) {
    std::cerr << "[ERROR] Failed to create data buffer: " << gpgme_strerror(err)
              << "\n";
    gpgme_release(ctx);
    return "";
  }

  err = gpgme_op_import(ctx, keyDataObj);
  if (err) {
    std::cerr << "[ERROR] Failed to import key: " << gpgme_strerror(err)
              << "\n";
    gpgme_data_release(keyDataObj);
    gpgme_release(ctx);
    return "";
  }

  std::cout << "[INFO] Public key imported into GPG context (not persisted).\n";

  err = gpgme_op_keylist_start(ctx, nullptr, 0);
  if (err) {
    std::cerr << "[ERROR] Failed to start key listing.\n";
    gpgme_data_release(keyDataObj);
    gpgme_release(ctx);
    return "";
  }

  while ((err = gpgme_op_keylist_next(ctx, &key)) == 0) {
    std::cout << "+----------------------------------+\n";
    std::cout << "| Key Fingerprint: " << key->subkeys->fpr << "\n";
    if (key->uids) {
      std::cout << "| User ID: " << key->uids->uid << "\n";
    }
    std::cout << "+----------------------------------+\n";
    gpgme_key_unref(key);
  }

  gpgme_op_keylist_end(ctx);
  gpgme_data_release(keyDataObj);
  gpgme_release(ctx);

  return keyData; // ✅ Return the key content
}
