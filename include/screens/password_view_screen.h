#ifndef PASSWORD_VIEW_SCREEN_H
#define PASSWORD_VIEW_SCREEN_H

#include "config/config_manager.h"
#include "screen_interface.h"
#include "screens/screen_manager.h"

class PasswordViewScreen : public PaneInterface {
public:
  PasswordViewScreen(ScreenManager *manager, AppConfig *config);
  void render() override;
  void handle_input(std::string key) override;

private:
  ScreenManager *manager_;
  AppConfig *config_;
};

#endif
