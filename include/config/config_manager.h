#pragma once

#include <string>
#include <vector>

struct KeyReference {
  std::string path;
  std::string username;
};

struct AppConfig {
  std::string username;
  std::string dbConnection;
  KeyReference privateKey;
  std::vector<KeyReference> publicKeys;
};

class ConfigManager {
public:
  explicit ConfigManager(const std::string &configPath);
  bool load();
  bool save();
  AppConfig &getConfig();

private:
  std::string configPath_;
  AppConfig config_;
};
