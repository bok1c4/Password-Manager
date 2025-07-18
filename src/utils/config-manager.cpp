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

    config_.dbConnection = "postgres://user:pass@localhost:5432/passwords";
    config_.privateKeyPath = "/home/you/.keys/private.asc";
    config_.publicKeys = {"/home/you/.keys/public.asc",
                          "/mnt/shared/public_vm.asc"};

    return save();
  }

  json j;
  file >> j;

  config_.dbConnection = j["db_connection"];
  config_.privateKeyPath = j["private_key_path"];
  for (const auto &key : j["public_keys"]) {
    config_.publicKeys.push_back(key);
  }

  return true;
}

bool ConfigManager::save() {
  json j;
  j["db_connection"] = config_.dbConnection;
  j["private_key_path"] = config_.privateKeyPath;
  j["public_keys"] = config_.publicKeys;

  std::ofstream file(configPath_);
  if (!file.is_open())
    return false;

  file << j.dump(4);
  return true;
}

AppConfig &ConfigManager::getConfig() { return config_; }
