#ifndef PASSWORD_GENERATED_SCREEN_H
#define PASSWORD_GENERATED_SCREEN_H

#include "screen_interface.h"
#include <string>

class ScreenManager;

class PasswordGeneratedScreen : public PaneInterface {
public:
  explicit PasswordGeneratedScreen(ScreenManager *manager);

  void render() override;
  void handle_input(char key) override;

private:
  std::string generate_random_string(const size_t length = 12);
  std::string password;

  ScreenManager *manager_;
};

#endif // PASSWORD_GENERATED_SCREEN_H
