#ifndef PASSWORD_VIEW_SCREEN_H
#define PASSWORD_VIEW_SCREEN_H

#include "screen_interface.h"
#include "screens/screen_manager.h"

class PasswordViewScreen : public PaneInterface {
public:
  PasswordViewScreen(ScreenManager *manager);
  void render() override;
  void handle_input(char c) override;

private:
  ScreenManager *manager_;
};

#endif
