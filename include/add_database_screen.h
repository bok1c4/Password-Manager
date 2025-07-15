#ifndef ADD_DATABASE_SCREEN_H
#define ADD_DATABASE_SCREEN_H

#include "screen_interface.h"

class AddDatabaseScreen : public PaneInterface {
public:
  void render() override;
  void handle_input(char c) override;
};

#endif
