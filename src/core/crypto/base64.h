#pragma once
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace pwmgr::crypto {

// Single-line base64 (BIO_FLAGS_BASE64_NO_NL). The no-newline output is
// load-bearing: the stored v1 password blobs were written this way.
std::string base64_encode(const unsigned char* data, std::size_t len);
std::string base64_encode(std::string_view data);

// Decodes single-line base64. Throws std::runtime_error on malformed input.
std::vector<unsigned char> base64_decode(std::string_view encoded);

}  // namespace pwmgr::crypto
