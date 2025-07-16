#include "./screens/screen_manager.h"
#include <./screens/password_input_screen.h>
#include <iostream>

PasswordInputScreen::PasswordInputScreen(ScreenManager *manager)
    : manager_(manager), focus_index_(0) {}

void PasswordInputScreen::render() {}

void PasswordInputScreen::handle_input(char key) {
  std::cout << key << std::endl;
  // handle:
  // p, n, tab
}
