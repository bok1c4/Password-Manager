#include <string>

#include "crypto/base64.h"
#include "test_framework.h"

using namespace pwmgr::crypto;

TEST_CASE("base64 known-answer vectors") {
  CHECK_EQ(base64_encode("f"), std::string("Zg=="));
  CHECK_EQ(base64_encode("fo"), std::string("Zm8="));
  CHECK_EQ(base64_encode("foo"), std::string("Zm9v"));
  CHECK_EQ(base64_encode("foobar"), std::string("Zm9vYmFy"));
}

TEST_CASE("base64 output has no newline (load-bearing for v1 blobs)") {
  std::string big(1024, 'x');
  std::string enc = base64_encode(big);
  CHECK(enc.find('\n') == std::string::npos);
  CHECK(enc.find('\r') == std::string::npos);
}

TEST_CASE("base64 roundtrip across lengths") {
  for (std::size_t n : {1u, 15u, 16u, 17u, 255u, 1024u}) {
    std::string in(n, '\0');
    for (std::size_t i = 0; i < n; ++i)
      in[i] = static_cast<char>((i * 37 + 11) & 0xFF);
    std::string enc = base64_encode(in);
    auto dec = base64_decode(enc);
    std::string out(dec.begin(), dec.end());
    CHECK_EQ(out, in);
  }
}
