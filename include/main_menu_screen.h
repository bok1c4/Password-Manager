#ifndef HOME_PANE_H
#define HOME_PANE_H

#include "screen_interface.h"

class MainMenuScreen : public PaneInterface {
public:
  void render() override;
  void handle_input(char c) override;
};

#endif
