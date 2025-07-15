#ifndef PASSWORD_GENERETION_H
#define PASSWORD_GENERETION_H

#include "screen_interface.h"

class PasswordGeneretionScreen : public PaneInterface {
public:
  void render() override;
  void handle_input(char c) override;
};

#endif
