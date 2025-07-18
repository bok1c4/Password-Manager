#ifndef MANAGE_DATABASE_SCREEN
#define MANAGE_DATABASE_SCREEN

#include "config/config_manager.h"
#include "screen_interface.h"
#include "screens/screen_manager.h"

class ManageDatabaseScreen : public PaneInterface {
public:
  ManageDatabaseScreen(ScreenManager *manager, AppConfig *config);
  void render() override;
  void handle_input(std::string) override;

private:
  ScreenManager *manager_;
  AppConfig *config_;
};

#endif
