#ifndef PASSWORD_GENERATED_SCREEN_H
#define PASSWORD_GENERATED_SCREEN_H

#include "config/config_manager.h"
#include "screen_interface.h"
#include <string>

class ScreenManager;

class PasswordGeneratedScreen : public PaneInterface {
public:
  explicit PasswordGeneratedScreen(ScreenManager *manager, AppConfig *config);

  void render() override;
  void handle_input(std::string key) override;

private:
  std::string generate_random_string(const size_t length = 16);
  std::string password;
  AppConfig *config_;

  ScreenManager *manager_;
};

#endif // PASSWORD_GENERATED_SCREEN_H
