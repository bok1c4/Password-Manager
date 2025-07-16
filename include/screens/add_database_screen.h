#ifndef ADD_DATABASE_SCREEN_H
#define ADD_DATABASE_SCREEN_H

#include "screen_interface.h"
#include "screens/screen_manager.h"

class AddDatabaseScreen : public PaneInterface {
public:
  AddDatabaseScreen(ScreenManager *manager);
  void render() override;
  void handle_input(char c) override;

private:
  ScreenManager *manager_;
};

#endif
