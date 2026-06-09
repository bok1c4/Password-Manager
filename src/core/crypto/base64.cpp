#include "crypto/base64.h"

#include <stdexcept>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

namespace pwmgr::crypto {

std::string base64_encode(const unsigned char* data, std::size_t length) {
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* mem = BIO_new(BIO_s_mem());
  BIO* bio = BIO_push(b64, mem);

  // Single line, no newlines -- load-bearing for the stored v1 blobs.
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  BIO_write(bio, data, static_cast<int>(length));
  BIO_flush(bio);

  BUF_MEM* ptr = nullptr;
  BIO_get_mem_ptr(bio, &ptr);
  std::string encoded(ptr->data, ptr->length);

  BIO_free_all(bio);
  return encoded;
}

std::string base64_encode(std::string_view data) {
  return base64_encode(reinterpret_cast<const unsigned char*>(data.data()),
                       data.size());
}

std::vector<unsigned char> base64_decode(std::string_view encoded) {
  const int max_len = static_cast<int>(encoded.size());
  std::vector<unsigned char> buffer(static_cast<std::size_t>(max_len) + 1, 0);

  BIO* b64 = BIO_new(BIO_f_base64());
  if (!b64) throw std::runtime_error("Failed to create BIO for base64.");

  BIO* mem = BIO_new_mem_buf(encoded.data(), max_len);
  if (!mem) {
    BIO_free(b64);
    throw std::runtime_error("Failed to create memory BIO.");
  }

  BIO* bio = BIO_push(b64, mem);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  int decoded_len = BIO_read(bio, buffer.data(), max_len);
  BIO_free_all(bio);

  if (decoded_len <= 0) throw std::runtime_error("Base64 decode failed.");

  buffer.resize(static_cast<std::size_t>(decoded_len));
  return buffer;
}

}  // namespace pwmgr::crypto
