#include "config/config.h"

#include <config/json.hpp>

#include <cstdlib>
#include <fstream>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace pwmgr::config {

std::string AppConfig::recipient_fingerprint() const {
  for (const auto& k : public_keys)
    if (!k.fingerprint.empty()) return k.fingerprint;
  return {};
}

std::string AppConfig::effective_device_name() const {
  if (!device_name.empty()) return device_name;
  if (!username.empty()) return username;
  return "founding-device";
}

fs::path ConfigManager::default_path() {
  if (const char* p = std::getenv("PWMGR_CONFIG"); p && *p) return fs::path(p);
  if (const char* x = std::getenv("XDG_CONFIG_HOME"); x && *x)
    return fs::path(x) / "pwmgr" / "config.json";
  const char* home = std::getenv("HOME");
  return fs::path(home ? home : ".") / ".config" / "pwmgr" / "config.json";
}

ConfigManager::ConfigManager(fs::path path) : path_(std::move(path)) {}

static KeyRef parse_key(const json& k) {
  KeyRef r;
  r.path = k.value("path", "");
  r.username = k.value("username", "");
  r.fingerprint = k.value("fingerprint", "");
  return r;
}

AppConfig ConfigManager::load() const {
  if (!fs::exists(path_)) {
    throw ConfigError("Config file not found: " + path_.string() +
                      " (set PWMGR_CONFIG or create it; refusing to write a "
                      "default that could repoint your data)");
  }
  std::ifstream in(path_);
  if (!in) throw ConfigError("Cannot open config: " + path_.string());

  json j;
  try {
    in >> j;
  } catch (const std::exception& e) {
    throw ConfigError(std::string("Malformed config JSON: ") + e.what());
  }

  AppConfig c;
  c.username = j.value("username", "");
  c.device_name = j.value("device_name", "");
  c.db_connection = j.value("db_connection", "");
  if (j.contains("private_key")) c.private_key = parse_key(j["private_key"]);
  if (j.contains("public_keys")) {
    for (const auto& pk : j["public_keys"]) c.public_keys.push_back(parse_key(pk));
  }

  if (c.db_connection.empty())
    throw ConfigError("config invalid: db_connection is empty");
  if (c.recipient_fingerprint().empty()) {
    throw ConfigError(
        "config invalid: no public key carries a fingerprint (cannot "
        "determine the encryption recipient)");
  }
  return c;
}

void ConfigManager::save(const AppConfig& c) const {
  // Validate on write so even a buggy caller cannot poison the file.
  if (c.recipient_fingerprint().empty())
    throw ConfigError("refusing to save config with no recipient fingerprint");
  if (c.private_key.path.empty())
    throw ConfigError("refusing to save config with an empty private key path");

  json j;
  j["username"] = c.username;
  if (!c.device_name.empty()) j["device_name"] = c.device_name;
  j["db_connection"] = c.db_connection;
  j["private_key"] = {{"path", c.private_key.path},
                      {"username", c.private_key.username}};
  if (!c.private_key.fingerprint.empty())
    j["private_key"]["fingerprint"] = c.private_key.fingerprint;
  j["public_keys"] = json::array();
  for (const auto& k : c.public_keys) {
    json kj = {{"path", k.path}, {"username", k.username}};
    if (!k.fingerprint.empty()) kj["fingerprint"] = k.fingerprint;
    j["public_keys"].push_back(kj);
  }
  const std::string data = j.dump(4);

  if (path_.has_parent_path()) fs::create_directories(path_.parent_path());
  const std::string tmp = path_.string() + ".tmp";

  int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) throw ConfigError("cannot open temp config for writing: " + tmp);
  const char* p = data.data();
  std::size_t left = data.size();
  while (left > 0) {
    ssize_t w = ::write(fd, p, left);
    if (w <= 0) {
      ::close(fd);
      throw ConfigError("write failed for " + tmp);
    }
    p += w;
    left -= static_cast<std::size_t>(w);
  }
  ::fsync(fd);
  ::close(fd);
  fs::rename(tmp, path_);  // atomic replace
}

std::string effective_db_connection(const AppConfig& c) {
  const std::string& s = c.db_connection;
  // URI form: never append a space-separated keyword (invalid for URIs). Let
  // libpq pick the password up from PGPASSWORD / ~/.pgpass instead.
  if (s.rfind("postgres://", 0) == 0 || s.rfind("postgresql://", 0) == 0)
    return s;
  // key=value form: only append if no password is already present.
  if (s.find("password=") != std::string::npos) return s;
  if (const char* pw = std::getenv("PWMGR_DB_PASSWORD"); pw && *pw)
    return s + " password=" + pw;
  return s;
}

}  // namespace pwmgr::config
