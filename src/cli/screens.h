#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "screen.h"

namespace pwmgr::cli {

class MainMenuScreen : public Screen {
 public:
  MainMenuScreen(ScreenManager* m, AppContext* c) : m_(m), c_(c) {}
  void render() override;
  void handle_input(const std::string& line) override;

 private:
  ScreenManager* m_;
  AppContext* c_;
};

class GenerateScreen : public Screen {
 public:
  GenerateScreen(ScreenManager* m, AppContext* c) : m_(m), c_(c) {}
  void render() override;
  void handle_input(const std::string& line) override;

 private:
  ScreenManager* m_;
  AppContext* c_;
  std::string password_ = generate_password_();
  static std::string generate_password_();
};

class ListScreen : public Screen {
 public:
  ListScreen(ScreenManager* m, AppContext* c) : m_(m), c_(c) {}
  void render() override;
  void handle_input(const std::string& line) override;

 private:
  ScreenManager* m_;
  AppContext* c_;
  std::optional<std::string> filter_;
};

class EntryScreen : public Screen {
 public:
  EntryScreen(ScreenManager* m, AppContext* c, std::int64_t id)
      : m_(m), c_(c), id_(id) {}
  void render() override;
  void handle_input(const std::string& line) override;

 private:
  ScreenManager* m_;
  AppContext* c_;
  std::int64_t id_;
};

class DevicesScreen : public Screen {
 public:
  DevicesScreen(ScreenManager* m, AppContext* c) : m_(m), c_(c) {}
  void render() override;
  void handle_input(const std::string& line) override;

 private:
  ScreenManager* m_;
  AppContext* c_;
};

class ManageDbScreen : public Screen {
 public:
  ManageDbScreen(ScreenManager* m, AppContext* c) : m_(m), c_(c) {}
  void render() override;
  void handle_input(const std::string& line) override;

 private:
  ScreenManager* m_;
  AppContext* c_;
};

class EncryptionScreen : public Screen {
 public:
  EncryptionScreen(ScreenManager* m, AppContext* c) : m_(m), c_(c) {}
  void render() override;
  void handle_input(const std::string& line) override;

 private:
  ScreenManager* m_;
  AppContext* c_;
};

}  // namespace pwmgr::cli
