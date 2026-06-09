#pragma once
#include <string>
#include <string_view>

namespace pwmgr::crypto {

// Decrypt ASCII-armored OpenPGP data using the user's GnuPG keyring. May invoke
// pinentry for the passphrase. Throws std::runtime_error on failure (callers
// must distinguish a thrown error from a legitimately empty plaintext).
std::string gpg_decrypt(std::string_view armored);

// Encrypt `plaintext` to the recipient identified by a full 40-char
// fingerprint, returning ASCII-armored ciphertext. The recipient is looked up
// in the keyring by fingerprint and the encrypt result is verified to target
// exactly that key. Throws std::runtime_error on failure / recipient mismatch.
std::string gpg_encrypt_to_fingerprint(std::string_view plaintext,
                                       std::string_view fingerprint);

// True if a usable SECRET key for `fingerprint` exists in the keyring.
bool gpg_has_secret_key(std::string_view fingerprint);

}  // namespace pwmgr::crypto
