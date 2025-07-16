#ifndef PASSWORD_GENERETION_H
#define PASSWORD_GENERETION_H

#include "screen_interface.h"
class ScreenManager;

class PasswordGenerationScreen : public PaneInterface {
public:
  PasswordGenerationScreen(ScreenManager *manager) : manager_(manager) {}

  void render() override;
  void handle_input(char c) override;

private:
  ScreenManager *manager_;
};

#endif
