#pragma once
#include <memory>
#include <stack>
#include <string>

namespace pwmgr {
namespace config {
struct AppConfig;
class ConfigManager;
}  // namespace config
namespace db {
class Repository;
}
namespace crypto {
class Encryptor;
}
namespace sharing {
class KeyStore;
}
}  // namespace pwmgr

namespace pwmgr::cli {

// Shared services handed to every screen (non-owning pointers).
struct AppContext {
  config::AppConfig* config;
  config::ConfigManager* cfgmgr;
  db::Repository* repo;
  crypto::Encryptor* enc;
  sharing::KeyStore* keys;
};

class Screen {
 public:
  virtual ~Screen() = default;
  virtual void render() = 0;
  virtual void handle_input(const std::string& line) = 0;
};

class ScreenManager {
 public:
  void push(std::unique_ptr<Screen> s) { stack_.push(std::move(s)); }
  void pop() {
    if (!stack_.empty()) stack_.pop();
  }
  Screen* current() { return stack_.empty() ? nullptr : stack_.top().get(); }
  bool empty() const { return stack_.empty(); }

 private:
  std::stack<std::unique_ptr<Screen>> stack_;
};

}  // namespace pwmgr::cli
