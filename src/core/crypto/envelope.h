#pragma once
#include <string>
#include <string_view>

namespace pwmgr::crypto {

enum class Version { V1_Cbc = 1, V2_Gcm = 2 };

// New (v2) password blobs are prefixed with this literal. ':' is not a base64
// character, so a legacy v1 blob (pure base64) can never begin with "v2:" --
// this makes read dispatch unambiguous.
inline constexpr std::string_view kV2Prefix = "v2:";

struct ParsedBlob {
  Version version;
  std::string payload;  // v1: the whole base64 string; v2: the part after "v2:"
};

// Dispatches on the "v2:" prefix; absence => v1 legacy.
ParsedBlob parse_password_blob(std::string_view stored);

// Wraps a v2 base64 payload with the version prefix.
std::string serialize_v2(std::string_view base64_payload);

}  // namespace pwmgr::crypto
