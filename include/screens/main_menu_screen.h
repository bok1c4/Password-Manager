#ifndef MAIN_MENU_SCREEN_H
#define MAIN_MENU_SCREEN_H

#include "screen_interface.h"
class ScreenManager;

class MainMenuScreen : public PaneInterface {
public:
  MainMenuScreen(ScreenManager *manager);

  void render() override;
  void handle_input(std::string input) override;

private:
  ScreenManager *manager_;
};

#endif
