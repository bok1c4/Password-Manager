#include "../utils/crypto.h"
#include <fstream>
#include <gpgme.h>
#include <iostream>
#include <optional>
#include <sstream>
#include <vector>

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

  return keyData;
}

std::optional<std::string> Encryptor::match_username_from_public_keys(
    const std::string &privKeyPath,
    const std::vector<KeyReference> &publicKeys) {

  gpgme_check_version(nullptr);
  gpgme_ctx_t ctx = nullptr;
  gpgme_error_t err = gpgme_new(&ctx);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create GPGME context: "
              << gpgme_strerror(err) << "\n";
    return std::nullopt;
  }
  gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

  // Load private key file content
  std::ifstream privFile(privKeyPath);
  if (!privFile) {
    std::cerr << "[ERROR] Could not open private key file: " << privKeyPath
              << "\n";
    gpgme_release(ctx);
    return std::nullopt;
  }
  std::stringstream privBuffer;
  privBuffer << privFile.rdbuf();
  std::string privKeyData = privBuffer.str();

  // Import private key into context
  gpgme_data_t privDataObj;
  err = gpgme_data_new_from_mem(&privDataObj, privKeyData.c_str(),
                                privKeyData.size(), 0);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create data buffer from private key: "
              << gpgme_strerror(err) << "\n";
    gpgme_release(ctx);
    return std::nullopt;
  }

  err = gpgme_op_import(ctx, privDataObj);
  gpgme_data_release(privDataObj);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to import private key: " << gpgme_strerror(err)
              << "\n";
    gpgme_release(ctx);
    return std::nullopt;
  }

  // List secret keys (private keys) from context and get fingerprint
  err = gpgme_op_keylist_start(ctx, nullptr, 1); // 1 = secret keys
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to start private key listing: "
              << gpgme_strerror(err) << "\n";
    gpgme_release(ctx);
    return std::nullopt;
  }

  gpgme_key_t privKey = nullptr;
  std::string privFingerprint;

  if (gpgme_op_keylist_next(ctx, &privKey) == GPG_ERR_NO_ERROR &&
      privKey != nullptr) {
    privFingerprint = privKey->subkeys->fpr;
    gpgme_key_unref(privKey);
  } else {
    std::cerr << "[ERROR] Could not find private key fingerprint.\n";
    gpgme_op_keylist_end(ctx);
    gpgme_release(ctx);
    return std::nullopt;
  }
  gpgme_op_keylist_end(ctx);

  // Now for each public key, import and compare fingerprints
  for (const auto &pubKeyRef : publicKeys) {
    // Load public key file content
    std::ifstream pubFile(pubKeyRef.path);
    if (!pubFile) {
      std::cerr << "[WARNING] Could not open public key file: "
                << pubKeyRef.path << "\n";
      continue;
    }
    std::stringstream pubBuffer;
    pubBuffer << pubFile.rdbuf();
    std::string pubKeyData = pubBuffer.str();

    // Import public key into context
    gpgme_data_t pubDataObj;
    err = gpgme_data_new_from_mem(&pubDataObj, pubKeyData.c_str(),
                                  pubKeyData.size(), 0);
    if (err != GPG_ERR_NO_ERROR) {
      std::cerr << "[WARNING] Failed to create data buffer from public key: "
                << gpgme_strerror(err) << "\n";
      continue;
    }

    err = gpgme_op_import(ctx, pubDataObj);
    gpgme_data_release(pubDataObj);
    if (err != GPG_ERR_NO_ERROR) {
      std::cerr << "[WARNING] Failed to import public key: "
                << gpgme_strerror(err) << "\n";
      continue;
    }

    // List public keys and check fingerprints
    err = gpgme_op_keylist_start(ctx, nullptr, 0); // 0 = public keys
    if (err != GPG_ERR_NO_ERROR) {
      std::cerr << "[WARNING] Failed to start public key listing: "
                << gpgme_strerror(err) << "\n";
      continue;
    }

    gpgme_key_t pubKey = nullptr;
    bool matched = false;
    while (gpgme_op_keylist_next(ctx, &pubKey) == GPG_ERR_NO_ERROR &&
           pubKey != nullptr) {
      std::string pubFingerprint = pubKey->subkeys->fpr;
      if (pubFingerprint == privFingerprint) {
        matched = true;
        gpgme_key_unref(pubKey);
        break;
      }
      gpgme_key_unref(pubKey);
    }

    gpgme_op_keylist_end(ctx);

    if (matched) {
      gpgme_release(ctx);
      return pubKeyRef.username;
    }
  }

  gpgme_release(ctx);
  return std::nullopt;
}

EncryptedPasswordsBeta Encryptor::encrypt_passwords_with_pks(
    const std::string &password, const std::vector<KeyReference> &publicKeys) {

  gpgme_check_version(nullptr);
  gpgme_ctx_t ctx;
  gpgme_error_t err = gpgme_new(&ctx);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create GPGME context: "
              << gpgme_strerror(err) << "\n";
    return {};
  }

  gpgme_set_armor(ctx, 1); // output ASCII armored

  // Import all recipient public keys to the keyring temporarily
  for (const auto &keyRef : publicKeys) {
    std::ifstream pubFile(keyRef.path);
    if (!pubFile) {
      std::cerr << "[WARNING] Cannot open public key file: " << keyRef.path
                << "\n";
      continue;
    }
    std::stringstream buffer;
    buffer << pubFile.rdbuf();
    std::string keyData = buffer.str();

    gpgme_data_t keyDataObj;
    err = gpgme_data_new_from_mem(&keyDataObj, keyData.c_str(), keyData.size(),
                                  0);
    if (err != GPG_ERR_NO_ERROR) {
      std::cerr << "[WARNING] Failed to create data object for public key: "
                << gpgme_strerror(err) << "\n";
      continue;
    }

    err = gpgme_op_import(ctx, keyDataObj);
    gpgme_data_release(keyDataObj);
    if (err != GPG_ERR_NO_ERROR) {
      std::cerr << "[WARNING] Failed to import public key: "
                << gpgme_strerror(err) << "\n";
      continue;
    }
  }

  // Collect recipients keys for encryption
  std::vector<gpgme_key_t> recipients;
  for (const auto &keyRef : publicKeys) {
    gpgme_key_t key;
    err = gpgme_op_keylist_start(ctx, nullptr, 0); // public keys
    if (err != GPG_ERR_NO_ERROR) {
      std::cerr << "[ERROR] Failed to start keylist: " << gpgme_strerror(err)
                << "\n";
      break;
    }

    bool found = false;
    while (gpgme_op_keylist_next(ctx, &key) == GPG_ERR_NO_ERROR) {
      if (key && std::string(key->uids->uid) == keyRef.username) {
        recipients.push_back(key);
        found = true;
        break;
      }
      if (key)
        gpgme_key_unref(key);
    }
    gpgme_op_keylist_end(ctx);
    if (!found) {
      std::cerr << "[WARNING] Could not find key for username: "
                << keyRef.username << "\n";
    }
  }

  if (recipients.empty()) {
    std::cerr << "[ERROR] No recipients found for encryption.\n";
    gpgme_release(ctx);
    return {};
  }

  // Prepare data for encryption
  gpgme_data_t plaintext, ciphertext;
  gpgme_data_new_from_mem(&plaintext, password.c_str(), password.size(), 0);
  gpgme_data_new(&ciphertext);

  // Encrypt to multiple recipients
  err = gpgme_op_encrypt(ctx, recipients.data(), GPGME_ENCRYPT_ALWAYS_TRUST,
                         plaintext, ciphertext);

  // Free recipients keys
  for (auto &k : recipients) {
    if (k)
      gpgme_key_unref(k);
  }
  gpgme_data_release(plaintext);

  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Encryption failed: " << gpgme_strerror(err) << "\n";
    gpgme_data_release(ciphertext);
    gpgme_release(ctx);
    return {};
  }

  // Extract encrypted data from ciphertext object
  ssize_t encrypted_len = gpgme_data_seek(ciphertext, 0, SEEK_END);
  gpgme_data_seek(ciphertext, 0, SEEK_SET);

  size_t size = 0;
  char *encrypted_buf = gpgme_data_release_and_get_mem(ciphertext, &size);
  std::string encryptedText;
  if (encrypted_buf && size > 0) {
    encryptedText.assign(encrypted_buf, size);
  }

  gpgme_data_release(ciphertext);
  gpgme_release(ctx);

  return {encryptedText};
}

std::string Encryptor::decrypt_password(const std::string &encryptedData) {
  gpgme_check_version(nullptr);
  gpgme_ctx_t ctx;
  gpgme_error_t err = gpgme_new(&ctx);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create GPGME context: "
              << gpgme_strerror(err) << "\n";
    return "";
  }
  gpgme_set_armor(ctx, 1);

  gpgme_data_t cipherData, plainData;
  err = gpgme_data_new_from_mem(&cipherData, encryptedData.c_str(),
                                encryptedData.size(), 0);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create cipher data object: "
              << gpgme_strerror(err) << "\n";
    gpgme_release(ctx);
    return "";
  }
  err = gpgme_data_new(&plainData);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create plain data object: "
              << gpgme_strerror(err) << "\n";
    gpgme_data_release(cipherData);
    gpgme_release(ctx);
    return "";
  }

  err = gpgme_op_decrypt(ctx, cipherData, plainData);
  gpgme_data_release(cipherData);

  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Decryption failed: " << gpgme_strerror(err) << "\n";
    gpgme_data_release(plainData);
    gpgme_release(ctx);
    return "";
  }

  off_t size_off = gpgme_data_seek(plainData, 0, SEEK_END);
  if (size_off < 0) {
    std::cerr << "[ERROR] Failed to get decrypted data size\n";
    gpgme_data_release(plainData);
    gpgme_release(ctx);
    return "";
  }
  size_t size = static_cast<size_t>(size_off);
  gpgme_data_seek(plainData, 0, SEEK_SET);

  std::string decryptedPassword(size, '\0');
  ssize_t bytesRead = gpgme_data_read(plainData, &decryptedPassword[0], size);
  if (bytesRead < 0) {
    std::cerr << "[ERROR] Failed to read decrypted data\n";
    gpgme_data_release(plainData);
    gpgme_release(ctx);
    return "";
  }

  gpgme_data_release(plainData);
  gpgme_release(ctx);

  return decryptedPassword;
}
