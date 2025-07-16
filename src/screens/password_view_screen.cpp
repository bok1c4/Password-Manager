
#include "./screens/password_view_screen.h"
#include "screens/screen_manager.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

PasswordViewScreen::PasswordViewScreen(ScreenManager *manager)
    : manager_(manager) {};

void PasswordViewScreen::render() {
  std::string view_pw_art = R"(
+============================================+
|             STORED PASSWORDS               |
+--------------------------------------------+
|  [List of Saved Password Entries]          |
|                                            |
|  Use ID or keyword to view specific entry  |
|                                            |
|  [b] Back to Home                          |
+============================================+

Waiting for command: 
)";
  std::cout << view_pw_art;
}

void PasswordViewScreen::handle_input(char key) {
  if (key == 'b') {
    manager_->pop();
    std::cout << "\n[INFO] Returning to Home Pane...\n";
  }
}
