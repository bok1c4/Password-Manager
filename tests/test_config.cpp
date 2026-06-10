#include <cstdlib>
#include <fstream>
#include <string>

#include <unistd.h>

#include "config/config.h"
#include "test_framework.h"

using namespace pwmgr::config;

namespace {
std::string tmpbase() {
  return "/tmp/pwmgr_cfg_test_" + std::to_string(::getpid());
}
}  // namespace

TEST_CASE("load: missing file throws and does NOT create a default") {
  std::string p = tmpbase() + "/missing.json";
  ConfigManager cm(p);
  CHECK_THROWS(cm.load());
  std::ifstream f(p);
  CHECK(!f.good());  // the data-repoint regression: nothing was written
}

TEST_CASE("save + load roundtrip") {
  std::string p = tmpbase() + "/cfg.json";
  AppConfig c;
  c.username = "arch";
  c.db_connection = "host=localhost dbname=pwmgr user=pwmgr password=x";
  c.private_key = {"/home/user/.gnupg/secret-key.asc", "arch", ""};
  c.public_keys.push_back(
      {"/home/user/Desktop/name", "arch",
       "29974BE04FCC7C31C4D1493730D6A019C21A600C"});

  ConfigManager cm(p);
  cm.save(c);
  AppConfig loaded = cm.load();
  CHECK_EQ(loaded.recipient_fingerprint(), c.recipient_fingerprint());
  CHECK_EQ(loaded.db_connection, c.db_connection);
  CHECK_EQ(loaded.username, std::string("arch"));
}

TEST_CASE("device_name round-trips through save + load") {
  std::string p = tmpbase() + "/devname.json";
  AppConfig c;
  c.username = "arch";
  c.device_name = "arch-desktop";
  c.db_connection = "host=localhost dbname=pwmgr user=pwmgr";
  c.private_key = {"/some/key.asc", "arch", ""};
  c.public_keys.push_back(
      {"/p", "arch", "29974BE04FCC7C31C4D1493730D6A019C21A600C"});
  ConfigManager cm(p);
  cm.save(c);
  CHECK_EQ(cm.load().device_name, std::string("arch-desktop"));
}

TEST_CASE("effective_device_name falls back device_name -> username -> default") {
  AppConfig c;
  CHECK_EQ(c.effective_device_name(), std::string("founding-device"));
  c.username = "arch";
  CHECK_EQ(c.effective_device_name(), std::string("arch"));
  c.device_name = "arch-desktop";
  CHECK_EQ(c.effective_device_name(), std::string("arch-desktop"));
}

TEST_CASE("legacy config JSON without device_name still loads") {
  std::string p = tmpbase() + "/legacy.json";
  AppConfig c;
  c.username = "arch";
  c.db_connection = "host=localhost dbname=pwmgr user=pwmgr";
  c.private_key = {"/some/key.asc", "arch", ""};
  c.public_keys.push_back(
      {"/p", "arch", "29974BE04FCC7C31C4D1493730D6A019C21A600C"});
  ConfigManager cm(p);
  cm.save(c);  // device_name empty -> key omitted from the JSON
  AppConfig loaded = cm.load();
  CHECK_EQ(loaded.device_name, std::string());
  CHECK_EQ(loaded.effective_device_name(), std::string("arch"));
}

TEST_CASE("save refuses a poisoned config (empty recipient fingerprint)") {
  std::string p = tmpbase() + "/poison.json";
  AppConfig c;
  c.db_connection = "host=localhost dbname=pwmgr";
  c.private_key = {"/some/key.asc", "arch", ""};
  c.public_keys.push_back({"/p", "arch", ""});  // empty fingerprint -> poison
  ConfigManager cm(p);
  CHECK_THROWS(cm.save(c));
}

TEST_CASE("default_path honors PWMGR_CONFIG over CWD/XDG") {
  setenv("PWMGR_CONFIG", "/tmp/custom/pwmgr.json", 1);
  CHECK_EQ(ConfigManager::default_path().string(),
           std::string("/tmp/custom/pwmgr.json"));
  unsetenv("PWMGR_CONFIG");
}

TEST_CASE("effective_db_connection appends PWMGR_DB_PASSWORD only when absent") {
  AppConfig with_pw;
  with_pw.db_connection = "host=localhost dbname=pwmgr password=abc";
  setenv("PWMGR_DB_PASSWORD", "fromenv", 1);
  CHECK_EQ(effective_db_connection(with_pw), with_pw.db_connection);

  AppConfig without_pw;
  without_pw.db_connection = "host=localhost dbname=pwmgr";
  CHECK_EQ(effective_db_connection(without_pw),
           std::string("host=localhost dbname=pwmgr password=fromenv"));
  unsetenv("PWMGR_DB_PASSWORD");
}

TEST_CASE("effective_db_connection never appends a keyword to a postgres:// URI") {
  setenv("PWMGR_DB_PASSWORD", "fromenv", 1);
  AppConfig uri;
  uri.db_connection = "postgres://pwmgr@localhost:5432/pwmgr";
  // Must be returned unchanged (libpq reads the password from PGPASSWORD/.pgpass).
  CHECK_EQ(effective_db_connection(uri), uri.db_connection);
  unsetenv("PWMGR_DB_PASSWORD");
}
