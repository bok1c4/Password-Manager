#pragma once
#include <string>
#include <vector>

struct AppConfig {
  std::string dbConnection;
  std::string privateKeyPath;
  std::vector<std::string> publicKeys;
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
