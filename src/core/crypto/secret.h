#pragma once
#include <cstddef>
#include <vector>

#include <openssl/crypto.h>

namespace pwmgr::crypto {

// Move-only byte buffer that wipes its contents (OPENSSL_cleanse) on
// destruction. Used to hold raw AES key material and decrypted plaintext so
// secrets do not linger in freed heap memory.
class SecureBytes {
 public:
  SecureBytes() = default;
  explicit SecureBytes(std::vector<unsigned char> v) : data_(std::move(v)) {}
  SecureBytes(const SecureBytes&) = delete;
  SecureBytes& operator=(const SecureBytes&) = delete;
  SecureBytes(SecureBytes&& o) noexcept { data_.swap(o.data_); }
  SecureBytes& operator=(SecureBytes&& o) noexcept {
    clear();
    data_.swap(o.data_);
    return *this;
  }
  ~SecureBytes() { clear(); }

  std::vector<unsigned char>& bytes() { return data_; }
  const std::vector<unsigned char>& bytes() const { return data_; }
  std::size_t size() const { return data_.size(); }

  void clear() {
    if (!data_.empty()) {
      OPENSSL_cleanse(data_.data(), data_.size());
      data_.clear();
    }
  }

 private:
  std::vector<unsigned char> data_;
};

}  // namespace pwmgr::crypto
