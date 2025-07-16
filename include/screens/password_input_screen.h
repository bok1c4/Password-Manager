#include "./screens/screen_interface.h"
#include "./screens/screen_manager.h"
#include <ostream>
#include <string>
#ifndef PASSWORD_INPUT_SCREEN_H
#define PASSWORD_INPUT_SCREEN_H()

class PasswordInputScreen : public PaneInterface {
public:
  PasswordInputScreen(ScreenManager *current);
  void render() override;
  void handle_input(char input) override;

private:
  ScreenManager *manager_;
  PaneInterface *current;
  std::string password_input_;
  int focus_index_; // 0: input field, 1: back button
};

#endif // !DEBUG
