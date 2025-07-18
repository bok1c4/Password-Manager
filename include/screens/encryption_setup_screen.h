#ifndef ENCRYPTION_SETUP_SCREEN_H
#define ENCRYPTION_SETUP_SCREEN_H

#include "screen_interface.h"
#include "screens/screen_manager.h"

class EncryptionSetupScreen : public PaneInterface {
public:
  EncryptionSetupScreen(ScreenManager *manager);
  void render() override;
  void handle_input(std::string input) override;

private:
  ScreenManager *manager_;
};

#endif
