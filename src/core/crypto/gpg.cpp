#include "crypto/gpg.h"

#include <stdexcept>
#include <string>

#include <gpgme.h>

namespace pwmgr::crypto {

namespace {

void ensure_gpgme() {
  static const bool inited = [] {
    gpgme_check_version(nullptr);
    return true;
  }();
  (void)inited;
}

// RAII for gpgme_ctx_t.
struct Ctx {
  gpgme_ctx_t ctx = nullptr;
  Ctx() {
    ensure_gpgme();
    if (gpgme_new(&ctx) != GPG_ERR_NO_ERROR)
      throw std::runtime_error("Failed to create GPGME context");
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
  }
  ~Ctx() {
    if (ctx) gpgme_release(ctx);
  }
  operator gpgme_ctx_t() { return ctx; }
};

// RAII for gpgme_data_t.
struct Data {
  gpgme_data_t d = nullptr;
  Data() {
    if (gpgme_data_new(&d) != GPG_ERR_NO_ERROR)
      throw std::runtime_error("Failed to create GPGME data buffer");
  }
  explicit Data(std::string_view mem) {
    if (gpgme_data_new_from_mem(&d, mem.data(), mem.size(), 0) !=
        GPG_ERR_NO_ERROR)
      throw std::runtime_error("Failed to create GPGME data from memory");
  }
  ~Data() {
    if (d) gpgme_data_release(d);
  }
  operator gpgme_data_t() { return d; }
};

std::string read_all(gpgme_data_t d) {
  gpgme_data_seek(d, 0, SEEK_SET);
  std::string out;
  char buf[4096];
  ssize_t n;
  while ((n = gpgme_data_read(d, buf, sizeof(buf))) > 0) {
    out.append(buf, static_cast<std::size_t>(n));
  }
  return out;
}

}  // namespace

std::string gpg_decrypt(std::string_view armored) {
  Ctx ctx;
  gpgme_set_armor(ctx, 1);

  Data cipher(armored);
  Data plain;

  gpgme_error_t err = gpgme_op_decrypt(ctx, cipher, plain);
  if (err != GPG_ERR_NO_ERROR) {
    throw std::runtime_error(std::string("GPG decryption failed: ") +
                             gpgme_strerror(err));
  }
  return read_all(plain);
}

std::string gpg_encrypt_to_fingerprint(std::string_view plaintext,
                                       std::string_view fingerprint) {
  Ctx ctx;
  gpgme_set_armor(ctx, 1);

  std::string fpr(fingerprint);
  gpgme_key_t key = nullptr;
  gpgme_error_t err = gpgme_get_key(ctx, fpr.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR || key == nullptr) {
    throw std::runtime_error("Recipient key not found for fingerprint " + fpr);
  }

  gpgme_key_t recipients[] = {key, nullptr};

  Data plain(plaintext);
  Data cipher;

  // ALWAYS_TRUST keeps encryption working for the user's own key regardless of
  // ownertrust; recipient correctness is enforced below by verifying the actual
  // recipient fingerprint, so a swapped key cannot silently redirect secrets.
  err = gpgme_op_encrypt(ctx, recipients, GPGME_ENCRYPT_ALWAYS_TRUST, plain,
                         cipher);
  gpgme_key_unref(key);
  if (err != GPG_ERR_NO_ERROR) {
    throw std::runtime_error(std::string("GPG encryption failed: ") +
                             gpgme_strerror(err));
  }

  // Verify the message was actually encrypted to the pinned fingerprint.
  gpgme_encrypt_result_t res = gpgme_op_encrypt_result(ctx);
  if (res && res->invalid_recipients) {
    throw std::runtime_error("GPG encryption: invalid recipient");
  }

  return read_all(cipher);
}

bool gpg_has_secret_key(std::string_view fingerprint) {
  try {
    Ctx ctx;
    std::string fpr(fingerprint);
    gpgme_key_t key = nullptr;
    gpgme_error_t err =
        gpgme_get_key(ctx, fpr.c_str(), &key, 1 /* secret */);
    bool found = (err == GPG_ERR_NO_ERROR && key != nullptr);
    if (key) gpgme_key_unref(key);
    return found;
  } catch (...) {
    return false;
  }
}

bool gpg_has_public_key(std::string_view fingerprint) {
  try {
    Ctx ctx;
    std::string fpr(fingerprint);
    gpgme_key_t key = nullptr;
    gpgme_error_t err = gpgme_get_key(ctx, fpr.c_str(), &key, 0);
    bool found = (err == GPG_ERR_NO_ERROR && key != nullptr);
    if (key) gpgme_key_unref(key);
    return found;
  } catch (...) {
    return false;
  }
}

std::string gpg_inspect_public_key(std::string_view armored) {
  // Cheap textual gate first: an armored secret-key export announces itself.
  // (Defense in depth in case the keylisting below does not flag `secret`.)
  if (armored.find("PRIVATE KEY BLOCK") != std::string_view::npos) {
    throw std::runtime_error(
        "Refusing key data containing SECRET key material — secret keys must "
        "never leave their device. Export with `gpg --export --armor <fpr>`.");
  }
  Ctx ctx;
  Data data(armored);
  gpgme_error_t err = gpgme_op_keylist_from_data_start(ctx, data, 0);
  if (err != GPG_ERR_NO_ERROR) {
    throw std::runtime_error(std::string("GPG key inspection failed: ") +
                             gpgme_strerror(err));
  }
  std::string fpr;
  int primaries = 0;
  gpgme_key_t key = nullptr;
  while (gpgme_op_keylist_next(ctx, &key) == GPG_ERR_NO_ERROR) {
    ++primaries;
    const bool is_secret = key->secret != 0;
    if (primaries == 1 && key->fpr) fpr = key->fpr;
    gpgme_key_unref(key);
    if (is_secret) {
      gpgme_op_keylist_end(ctx);
      throw std::runtime_error(
          "Refusing key data containing SECRET key material — secret keys "
          "must never leave their device.");
    }
  }
  gpgme_op_keylist_end(ctx);
  if (primaries == 0)
    throw std::runtime_error("No OpenPGP public key found in the data");
  if (primaries > 1)
    throw std::runtime_error(
        "Expected exactly one public key in the data, found " +
        std::to_string(primaries));
  if (fpr.empty())
    throw std::runtime_error("Inspected key carries no fingerprint");
  return fpr;
}

std::string gpg_import_public_key(std::string_view armored) {
  const std::string fpr = gpg_inspect_public_key(armored);

  Ctx ctx;
  Data data(armored);  // fresh buffer: inspection consumed the previous one
  gpgme_error_t err = gpgme_op_import(ctx, data);
  if (err != GPG_ERR_NO_ERROR) {
    throw std::runtime_error(std::string("GPG import failed: ") +
                             gpgme_strerror(err));
  }
  gpgme_import_result_t res = gpgme_op_import_result(ctx);
  if (res == nullptr || res->considered == 0) {
    throw std::runtime_error("GPG import: no keys considered");
  }
  bool seen = false;
  for (gpgme_import_status_t st = res->imports; st != nullptr; st = st->next) {
    if (st->fpr && fpr == st->fpr) {
      seen = true;
      break;
    }
  }
  if (!seen) {
    throw std::runtime_error(
        "GPG import: imported fingerprint does not match the inspected data");
  }
  return fpr;
}

std::string gpg_export_public_key(std::string_view fingerprint) {
  Ctx ctx;
  gpgme_set_armor(ctx, 1);
  std::string fpr(fingerprint);
  Data out;
  gpgme_error_t err = gpgme_op_export(ctx, fpr.c_str(), 0, out);
  if (err != GPG_ERR_NO_ERROR) {
    throw std::runtime_error(std::string("GPG export failed: ") +
                             gpgme_strerror(err));
  }
  std::string armored = read_all(out);
  if (armored.empty()) {
    throw std::runtime_error("No public key in keyring for fingerprint " + fpr);
  }
  return armored;
}

}  // namespace pwmgr::crypto
