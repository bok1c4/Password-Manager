#include <string>

#include "crypto/envelope.h"
#include "test_framework.h"

using namespace pwmgr::crypto;

TEST_CASE("envelope dispatch: v2 prefix routes to GCM") {
  auto p = parse_password_blob("v2:Zm9vYmFy");
  CHECK(p.version == Version::V2_Gcm);
  CHECK_EQ(p.payload, std::string("Zm9vYmFy"));
}

TEST_CASE("envelope dispatch: bare base64 routes to v1 CBC") {
  auto p = parse_password_blob("oZLUTH5bDFaLuCtr3XDMhExWEQQo");
  CHECK(p.version == Version::V1_Cbc);
  CHECK_EQ(p.payload, std::string("oZLUTH5bDFaLuCtr3XDMhExWEQQo"));
}

TEST_CASE("serialize_v2 adds the prefix and round-trips") {
  std::string s = serialize_v2("abc123+/=");
  CHECK_EQ(s, std::string("v2:abc123+/="));
  auto p = parse_password_blob(s);
  CHECK(p.version == Version::V2_Gcm);
  CHECK_EQ(p.payload, std::string("abc123+/="));
}

TEST_CASE("legacy base64 can never begin with the v2 prefix") {
  // ':' is not in the base64 alphabet, so no v1 blob can collide with "v2:".
  CHECK(kV2Prefix.find(':') != std::string_view::npos);
}
