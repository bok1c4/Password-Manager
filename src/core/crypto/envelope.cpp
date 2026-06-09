#include "crypto/envelope.h"

namespace pwmgr::crypto {

ParsedBlob parse_password_blob(std::string_view stored) {
  if (stored.size() >= kV2Prefix.size() &&
      stored.substr(0, kV2Prefix.size()) == kV2Prefix) {
    return {Version::V2_Gcm, std::string(stored.substr(kV2Prefix.size()))};
  }
  return {Version::V1_Cbc, std::string(stored)};
}

std::string serialize_v2(std::string_view base64_payload) {
  std::string out;
  out.reserve(kV2Prefix.size() + base64_payload.size());
  out.append(kV2Prefix);
  out.append(base64_payload);
  return out;
}

}  // namespace pwmgr::crypto
