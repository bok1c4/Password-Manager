#ifndef PASSWORD_GENERATED_SCREEN_H
#define PASSWORD_GENERATED_SCREEN_H

#include "screen_interface.h"

class ScreenManager;

class PasswordGeneratedScreen : public PaneInterface {
public:
  PasswordGeneratedScreen(ScreenManager *manager);

  void render() override;
  void handle_input(char key) override;

private:
  ScreenManager *manager_;
};

#endif // !DEBUG
