#pragma once
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace pwmgr::crypto {

// Cryptographically secure random bytes (OpenSSL RAND_bytes). Throws on failure.
std::vector<unsigned char> random_bytes(std::size_t n);

// ---- v1 (LEGACY, READ-ONLY) ----
// Input is base64(IV(16) || AES-256-CBC ciphertext). This is byte-for-byte the
// original aes_decrypt_password algorithm and must never change: the 13
// existing rows depend on it. New writes never produce this format.
std::string aes256_cbc_decrypt(std::string_view base64_iv_ciphertext,
                               const std::vector<unsigned char>& key32);

// ---- v2 (NEW, AUTHENTICATED) ----
// Returns base64(nonce(12) || ciphertext || tag(16)) using AES-256-GCM.
std::string aes256_gcm_encrypt(std::string_view plaintext,
                               const std::vector<unsigned char>& key32);

// Verifies the GCM tag; throws std::runtime_error on tamper / wrong key.
std::string aes256_gcm_decrypt(std::string_view base64_nonce_ct_tag,
                               const std::vector<unsigned char>& key32);

}  // namespace pwmgr::crypto
