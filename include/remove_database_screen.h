#ifndef REMOVE_DATABASE_SCREEN_H
#define REMOVE_DATABASE_SCREEN_H

#include "screen_interface.h"

class RemoveDatabaseScreen : public PaneInterface {
public:
  void render() override;
  void handle_input(char c) override;
};

#endif
