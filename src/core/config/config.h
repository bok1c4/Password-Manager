#pragma once
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace pwmgr::config {

struct KeyRef {
  std::string path;
  std::string username;
  std::string fingerprint;
};

struct AppConfig {
  std::string username;
  std::string db_connection;
  KeyRef private_key;
  std::vector<KeyRef> public_keys;

  // The fingerprint new writes encrypt the AES key to: the first public key
  // that carries a fingerprint. Empty if none -> treated as invalid.
  std::string recipient_fingerprint() const;
};

class ConfigError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Resolves and (de)serializes the config from ONE absolute path. Never invents
// a default config on disk; load() fails loud if the file is missing/invalid.
class ConfigManager {
 public:
  // PWMGR_CONFIG > $XDG_CONFIG_HOME/pwmgr/config.json > ~/.config/pwmgr/config.json
  static std::filesystem::path default_path();

  explicit ConfigManager(std::filesystem::path path);

  AppConfig load() const;             // throws ConfigError on missing/invalid
  void save(const AppConfig&) const;  // atomic temp+fsync+rename, 0600, validated

  const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

// Applies PWMGR_DB_PASSWORD if the stored connection string lacks a password.
std::string effective_db_connection(const AppConfig&);

}  // namespace pwmgr::config
