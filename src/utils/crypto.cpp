#include "../utils/crypto.h"
#include "config/config_manager.h"
#include <cstring>
#include <fstream>
#include <gpgme.h>
#include <iostream>
#include <openssl/rand.h>
#include <optional>
#include <sstream>

#include <vector>

Encryptor::Encryptor(AppConfig *config) : config_(config) {}

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

  std::cout << "[INFO] Starting encryption process.\n";

  gpgme_check_version(nullptr);
  gpgme_ctx_t ctx;
  gpgme_error_t err = gpgme_new(&ctx);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create GPGME context: "
              << gpgme_strerror(err) << "\n";
    return {};
  }

  gpgme_set_armor(ctx, 1); // output ASCII armored
  std::cout << "[INFO] GPGME context created and ASCII armor enabled.\n";

  // Import all recipient public keys to the keyring temporarily
  for (const auto &keyRef : publicKeys) {
    std::cout << "[INFO] Processing public key: " << keyRef.path << "\n";

    std::ifstream pubFile(keyRef.path);
    if (!pubFile) {
      std::cerr << "[WARNING] Cannot open public key file: " << keyRef.path
                << "\n";
      continue;
    }
    std::stringstream buffer;
    buffer << pubFile.rdbuf();
    std::string keyData = buffer.str();
    std::cout << "[INFO] Read public key data from file.\n";

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
    } else {
      std::cout << "[INFO] Successfully imported public key.\n";
    }
  }

  std::vector<gpgme_key_t> recipients;

  for (const auto &keyRef : publicKeys) {
    std::cout << "[INFO] Looking up key with fingerprint: "
              << keyRef.fingerprint << "\n";

    gpgme_key_t key = nullptr;
    err = gpgme_op_keylist_start(ctx, keyRef.fingerprint.c_str(), 0);
    if (err != GPG_ERR_NO_ERROR) {
      std::cerr << "[ERROR] Failed to start keylist for fingerprint "
                << keyRef.fingerprint << ": " << gpgme_strerror(err) << "\n";
      continue;
    }

    err = gpgme_op_keylist_next(ctx, &key);
    if (err == GPG_ERR_NO_ERROR && key != nullptr) {
      std::cout << "[INFO] Key found and added to recipients.\n";
      recipients.push_back(key);
    } else {
      std::cerr << "[WARNING] Could not find key with fingerprint "
                << keyRef.fingerprint << "\n";
    }

    gpgme_op_keylist_end(ctx);
  }

  if (recipients.empty()) {
    std::cerr << "[ERROR] No recipients found for encryption.\n";
    gpgme_release(ctx);
    return {};
  }

  std::cout << "[INFO] Total recipients for encryption: " << recipients.size()
            << "\n";

  gpgme_data_t plaintext, ciphertext;
  err =
      gpgme_data_new_from_mem(&plaintext, password.c_str(), password.size(), 0);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create plaintext data buffer: "
              << gpgme_strerror(err) << "\n";
    gpgme_release(ctx);
    return {};
  }

  err = gpgme_data_new(&ciphertext);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create ciphertext data buffer: "
              << gpgme_strerror(err) << "\n";
    gpgme_data_release(plaintext);
    gpgme_release(ctx);
    return {};
  }

  std::cout << "[INFO] Encrypting data...\n";

  err = gpgme_op_encrypt(ctx, recipients.data(), GPGME_ENCRYPT_ALWAYS_TRUST,
                         plaintext, ciphertext);

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

  std::cout << "[INFO] Encryption successful.\n";

  ssize_t encrypted_len = gpgme_data_seek(ciphertext, 0, SEEK_END);
  std::cout << "[INFO] Encrypted length: " << encrypted_len << " bytes.\n";
  gpgme_data_seek(ciphertext, 0, SEEK_SET);

  size_t size = 0;
  char *encrypted_buf = gpgme_data_release_and_get_mem(ciphertext, &size);
  std::string encryptedText;
  if (encrypted_buf && size > 0) {
    std::cout << "[INFO] Retrieved encrypted buffer of size: " << size << "\n";
    encryptedText.assign(encrypted_buf, size);
  } else {
    std::cerr << "[ERROR] Failed to retrieve encrypted data.\n";
  }

  gpgme_release(ctx);
  std::cout << "[INFO] GPGME context released. Encryption process complete.\n";

  return {encryptedText};
}

std::string Encryptor::decrypt_password(const std::string &encryptedData,
                                        gpgme_ctx_t ctx) {
  gpgme_set_armor(ctx, 1);

  gpgme_data_t cipherData, plainData;
  gpgme_error_t err = gpgme_data_new_from_mem(
      &cipherData, encryptedData.c_str(), encryptedData.size(), 0);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create cipher data object: "
              << gpgme_strerror(err) << "\n";
    return "";
  }

  err = gpgme_data_new(&plainData);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create plain data object: "
              << gpgme_strerror(err) << "\n";
    gpgme_data_release(cipherData);
    return "";
  }

  err = gpgme_op_decrypt(ctx, cipherData, plainData);
  gpgme_data_release(cipherData);

  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Decryption failed: " << gpgme_strerror(err) << "\n";
    gpgme_data_release(plainData);
    return "";
  }

  size_t out_size = 0;
  char *out_buf = gpgme_data_release_and_get_mem(plainData, &out_size);
  if (!out_buf || out_size == 0) {
    std::cerr << "[ERROR] Decryption returned empty result\n";
    return "";
  }

  std::string decryptedPassword(out_buf, out_size);
  return decryptedPassword;
}

std::string Encryptor::generate_aes_key() {
  unsigned char key[32];
  if (RAND_bytes(key, sizeof(key)) != 1) {
    throw std::runtime_error("Failed to generate AES key");
  }
  return std::string(reinterpret_cast<char *>(key), sizeof(key));
}

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

std::string Encryptor::base64_encode(const unsigned char *buffer,
                                     size_t length) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  // Disable newlines - write everything in one line
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  BIO_write(bio, buffer, static_cast<int>(length));
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);

  std::string encoded(bufferPtr->data, bufferPtr->length);
  BIO_free_all(bio);

  return encoded;
}

std::string Encryptor::aes_encrypt_password(const std::string &password,
                                            const std::string &aes_key) {
  if (aes_key.size() != 32) {
    throw std::runtime_error("AES key must be 32 bytes for AES-256");
  }

  // Generate random IV (16 bytes)
  unsigned char iv[16];
  if (RAND_bytes(iv, sizeof(iv)) != 1) {
    throw std::runtime_error("Failed to generate random IV");
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP cipher context");
  }

  int len = 0;
  int ciphertext_len = 0;

  // Output buffer: ciphertext length can be up to input length + block size (16
  // bytes)
  std::vector<unsigned char> ciphertext(password.size() + 16);

  // Initialize encryption operation
  if (EVP_EncryptInit_ex(
          ctx, EVP_aes_256_cbc(), NULL,
          reinterpret_cast<const unsigned char *>(aes_key.data()), iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptInit_ex failed");
  }

  if (EVP_EncryptUpdate(
          ctx, ciphertext.data(), &len,
          reinterpret_cast<const unsigned char *>(password.data()),
          static_cast<int>(password.size())) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptUpdate failed");
  }
  ciphertext_len = len;

  // Finalize encryption (handle padding)
  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptFinal_ex failed");
  }
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  std::vector<unsigned char> output;
  output.reserve(16 + ciphertext_len);
  output.insert(output.end(), iv, iv + 16);
  output.insert(output.end(), ciphertext.begin(),
                ciphertext.begin() + ciphertext_len);

  return base64_encode(output.data(), output.size());
}

std::vector<unsigned char> base64_decode(const std::string &encoded) {
  BIO *bio = nullptr;
  BIO *b64 = nullptr;

  int maxLen = encoded.length();
  std::vector<unsigned char> buffer(maxLen);

  b64 = BIO_new(BIO_f_base64());
  if (!b64) {
    throw std::runtime_error("Failed to create BIO for base64.");
  }

  bio = BIO_new_mem_buf(encoded.data(), maxLen);
  if (!bio) {
    BIO_free(b64);
    throw std::runtime_error("Failed to create memory BIO.");
  }

  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Do not expect newlines

  int decodedLen = BIO_read(bio, buffer.data(), maxLen);
  BIO_free_all(bio);

  if (decodedLen <= 0) {
    throw std::runtime_error("Base64 decode failed.");
  }

  buffer.resize(decodedLen);
  return buffer;
}

std::string
Encryptor::aes_decrypt_password(const std::string &encrypted_base64,
                                const std::vector<unsigned char> &aes_key) {
  if (aes_key.size() != 32) {
    throw std::runtime_error("AES key must be 32 bytes for AES-256");
  }

  // Decode Base64 (IV + ciphertext)
  std::vector<unsigned char> decoded = base64_decode(encrypted_base64);

  if (decoded.size() <= 16) {
    throw std::runtime_error(
        "Decoded data too short to contain IV and ciphertext.");
  }

  // Extract IV
  unsigned char iv[16];
  std::memcpy(iv, decoded.data(), 16);

  const unsigned char *ciphertext = decoded.data() + 16;
  int ciphertext_len = decoded.size() - 16;

  // Prepare decryption context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP context");
  }

  std::vector<unsigned char> plaintext(ciphertext_len + 16);
  int outlen = 0, total_len = 0;

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key.data(), iv) !=
      1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptInit_ex failed");
  }

  if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext,
                        ciphertext_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptUpdate failed");
  }

  total_len = outlen;

  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptFinal_ex failed");
  }

  total_len += outlen;
  EVP_CIPHER_CTX_free(ctx);

  return std::string(reinterpret_cast<char *>(plaintext.data()), total_len);
}

bool Encryptor::load_private_key_for_decryption(
    const std::string &privKeyPath) {
  std::ifstream privFile(privKeyPath);
  if (!privFile) {
    std::cerr << "[ERROR] Could not open private key file: " << privKeyPath
              << "\n";
    return false;
  }

  std::stringstream buffer;
  buffer << privFile.rdbuf();
  std::string privKeyData = buffer.str();

  gpgme_ctx_t ctx;
  if (gpgme_new(&ctx) != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create GPGME context.\n";
    return false;
  }

  gpgme_data_t privData;
  gpgme_error_t err = gpgme_data_new_from_mem(&privData, privKeyData.c_str(),
                                              privKeyData.size(), 0);
  if (err) {
    std::cerr << "[ERROR] Failed to create data buffer: " << gpgme_strerror(err)
              << "\n";
    gpgme_release(ctx);
    return false;
  }

  err = gpgme_op_import(ctx, privData);
  gpgme_data_release(privData);
  gpgme_release(ctx);

  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to import private key: " << gpgme_strerror(err)
              << "\n";
    return false;
  }

  return true;
}

std::optional<gpgme_ctx_t>
Encryptor::load_gpgme_ctx_with_privkey(const std::string &privKeyPath) {
  gpgme_check_version(nullptr);
  gpgme_ctx_t ctx = nullptr;
  gpgme_error_t err = gpgme_new(&ctx);
  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create GPGME context: "
              << gpgme_strerror(err) << "\n";
    return std::nullopt;
  }
  gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

  // Read private key file
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

  // Import private key
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

  return ctx; // Return the context with the private key imported
}

std::string Encryptor::decrypt_hybrid(const std::string &encryptedPassword,
                                      const std::string &encryptedAesKey) {
  std::cout << "Private key file path: " << config_->privateKey.path
            << std::endl;

  // Load GPGME context with private key
  auto ctxOpt = load_gpgme_ctx_with_privkey(config_->privateKey.path);
  if (!ctxOpt) {
    std::cerr << "[ERROR] Failed to load private key context.\n";
    return "";
  }
  gpgme_ctx_t ctx = *ctxOpt;

  std::cout << "[INFO] Decrypting AES key...\n";
  std::string decrypted_aes_key = decrypt_password(encryptedAesKey, ctx);
  if (decrypted_aes_key.empty()) {
    std::cerr << "[ERROR] Failed to decrypt AES key.\n";
    gpgme_release(ctx);
    return "";
  }

  std::vector<unsigned char> decoded_aes_key(decrypted_aes_key.begin(),
                                             decrypted_aes_key.end());

  gpgme_release(ctx);

  // Debug print AES key hex and size
  std::cout << "[DEBUG] AES key (hex): ";
  for (unsigned char c : decoded_aes_key) {
    printf("%02X", c);
  }
  std::cout << "\n[DEBUG] AES key size: " << decoded_aes_key.size() << "\n";

  // Step 3: Decrypt the password using the decoded AES key
  try {
    return aes_decrypt_password(encryptedPassword, decoded_aes_key);
  } catch (const std::exception &e) {
    std::cerr << "[ERROR] AES decryption failed: " << e.what() << "\n";
    return "";
  }
}

std::string
Encryptor::get_fingerprint_from_pubkey(const std::string &pubKeyPath) {
  gpgme_check_version(nullptr);
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  if ((err = gpgme_new(&ctx)) != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create GPGME context: "
              << gpgme_strerror(err) << "\n";
    return "";
  }

  // Read key file
  std::ifstream file(pubKeyPath);
  if (!file.is_open()) {
    std::cerr << "[ERROR] Cannot open public key file: " << pubKeyPath << "\n";
    gpgme_release(ctx);
    return "";
  }
  std::stringstream buffer;
  buffer << file.rdbuf();
  std::string keyData = buffer.str();

  gpgme_data_t keyDataObj;
  if ((err = gpgme_data_new_from_mem(&keyDataObj, keyData.c_str(),
                                     keyData.size(), 0)) != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create data object: " << gpgme_strerror(err)
              << "\n";
    gpgme_release(ctx);
    return "";
  }

  if ((err = gpgme_op_import(ctx, keyDataObj)) != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to import key: " << gpgme_strerror(err)
              << "\n";
    gpgme_data_release(keyDataObj);
    gpgme_release(ctx);
    return "";
  }

  gpgme_import_result_t import_result = gpgme_op_import_result(ctx);
  if (!import_result || !import_result->imports ||
      !import_result->imports->fpr) {
    std::cerr << "[ERROR] No fingerprint found in import result.\n";
    gpgme_data_release(keyDataObj);
    gpgme_release(ctx);
    return "";
  }

  std::string fingerprint = import_result->imports->fpr;

  gpgme_data_release(keyDataObj);
  gpgme_release(ctx);
  return fingerprint;
}

bool Encryptor::import_private_key(const std::string &privateKeyPath) {
  std::ifstream in(privateKeyPath);
  if (!in) {
    std::cerr << "[ERROR] Cannot open private key: " << privateKeyPath << "\n";
    return false;
  }

  std::stringstream buffer;
  buffer << in.rdbuf();
  std::string keyData = buffer.str();

  gpgme_ctx_t ctx;
  if (gpgme_new(&ctx) != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to create GPGME context.\n";
    return false;
  }

  gpgme_data_t keyDataObj;
  gpgme_error_t err =
      gpgme_data_new_from_mem(&keyDataObj, keyData.c_str(), keyData.size(), 0);
  if (err) {
    std::cerr << "[ERROR] Failed to create key data buffer: "
              << gpgme_strerror(err) << "\n";
    gpgme_release(ctx);
    return false;
  }

  err = gpgme_op_import(ctx, keyDataObj);
  gpgme_data_release(keyDataObj);
  gpgme_release(ctx);

  if (err != GPG_ERR_NO_ERROR) {
    std::cerr << "[ERROR] Failed to import private key: " << gpgme_strerror(err)
              << "\n";
    return false;
  }

  std::cout << "[INFO] Private key successfully imported.\n";
  return true;
}
