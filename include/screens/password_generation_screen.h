#ifndef PASSWORD_GENERATION_SCREEN_H
#define PASSWORD_GENERATION_SCREEN_H

#include "config/config_manager.h"
#include "screen_interface.h"
#include <memory>

class ScreenManager;

class PasswordGenerationScreen : public PaneInterface {
public:
  explicit PasswordGenerationScreen(ScreenManager *manager, AppConfig *config);

  void render() override;
  void handle_input(std::string input) override;

private:
  ScreenManager *manager_;
  AppConfig *config_;
};

#endif
