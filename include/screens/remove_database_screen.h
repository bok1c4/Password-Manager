#ifndef REMOVE_DATABASE_SCREEN_H
#define REMOVE_DATABASE_SCREEN_H

#include "screen_interface.h"
#include "screens/screen_manager.h"

class RemoveDatabaseScreen : public PaneInterface {
public:
  RemoveDatabaseScreen(ScreenManager *manager);
  void render() override;
  void handle_input(std::string input) override;

private:
  ScreenManager *manager_;
};

#endif
