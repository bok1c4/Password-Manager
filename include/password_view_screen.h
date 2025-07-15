#ifndef PASSWORD_VIEW_SCREEN_H
#define PASSWORD_VIEW_SCREEN_H

#include "screen_interface.h"

class PasswordViewScreen : public PaneInterface {
public:
  void render() override;
  void handle_input(char c) override;
};

#endif
