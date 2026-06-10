#pragma once
#include <cstdint>
#include <string>
#include <string_view>

namespace pwmgr::db {

// One row of `devices`. enrolled_at is read as ::text and is display-only.
struct Device {
  std::int64_t id = 0;
  std::string name;
  std::string fingerprint;  // full 40-char upper-case hex GPG fingerprint
  std::string public_key;   // armored public key ("" until known)
  std::string status;       // 'active' | 'revoked'
  std::string enrolled_at;
};

// The identity migration v2 registers as the first device. Assembled by the
// CLI layer from the active config (never read back from the DB).
struct FoundingDevice {
  std::string name;               // AppConfig::effective_device_name()
  std::string fingerprint;        // AppConfig::recipient_fingerprint()
  std::string public_key_armored; // matching KeyRef file contents; "" if unreadable
};

// One armored GPG wrap destined for password_keys. Shared by Repository, the
// sharing KeyStore and the enroll/rotate engines — single definition.
struct WrappedKey {
  std::int64_t device_id;
  std::string armored;
};

// Exactly 40 hex characters (either case). No spaces, no prefixes.
bool is_valid_fingerprint(std::string_view fpr);

// Strips ASCII spaces (gpg prints fingerprints space-grouped), uppercases,
// then validates. Returns "" if the result is not a valid fingerprint.
std::string normalize_fingerprint(std::string_view fpr);

}  // namespace pwmgr::db
