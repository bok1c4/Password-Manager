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

// True if a PUBLIC key for `fingerprint` exists in the keyring.
bool gpg_has_public_key(std::string_view fingerprint);

// Inspects armored OpenPGP data WITHOUT writing anything to the keyring and
// returns the primary key's 40-char fingerprint. Throws if the data contains
// secret-key material (secret keys must never leave their device), no key, or
// more than one primary key. Used to verify an expected fingerprint BEFORE
// any import happens.
std::string gpg_inspect_public_key(std::string_view armored);

// gpg_inspect_public_key + import into the keyring; returns the fingerprint
// of what was actually imported (verified to match the inspection).
// Idempotent: re-importing a known key succeeds.
std::string gpg_import_public_key(std::string_view armored);

// Exports the armored PUBLIC key for `fingerprint`. Throws if absent/empty.
std::string gpg_export_public_key(std::string_view fingerprint);

}  // namespace pwmgr::crypto
