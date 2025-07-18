#include "config/config_manager.h"
#include <config/json.hpp>
#include <fstream>
#include <iostream>

using json = nlohmann::json;

ConfigManager::ConfigManager(const std::string &configPath)
    : configPath_(configPath) {}

bool ConfigManager::load() {
  std::ifstream file(configPath_);
  if (!file.is_open()) {
    std::cerr << "[INFO] Config file not found. Creating default config...\n";

    config_.username = "default-machine";
    config_.privateKey = {"/home/you/.keys/private.asc", "default-machine"};
    config_.publicKeys = {{"/home/you/.keys/public.asc", "default-machine"},
                          {"/mnt/shared/public_vm.asc", "vm-machine"}};
    config_.dbConnection = "postgres://user:pass@localhost:5432/passwords";

    return save();
  }

  json j;
  file >> j;

  config_.username = j.value("username", "default-machine");
  config_.dbConnection = j["db_connection"];

  auto priv = j["private_key"];
  config_.privateKey.path = priv["path"];
  config_.privateKey.username = priv["username"];

  config_.publicKeys.clear();
  for (const auto &pk : j["public_keys"]) {
    config_.publicKeys.push_back({pk["path"], pk["username"]});
  }

  return true;
}

bool ConfigManager::save() {
  json j;
  j["username"] = config_.username;
  j["db_connection"] = config_.dbConnection;

  j["private_key"] = {{"path", config_.privateKey.path},
                      {"username", config_.privateKey.username}};

  j["public_keys"] = json::array();
  for (const auto &pk : config_.publicKeys) {
    j["public_keys"].push_back({{"path", pk.path}, {"username", pk.username}});
  }

  std::ofstream file(configPath_);
  if (!file.is_open())
    return false;

  file << j.dump(4);
  return true;
}

AppConfig &ConfigManager::getConfig() { return config_; }
