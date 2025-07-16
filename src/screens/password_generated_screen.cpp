
#include "screens/password_generated_screen.h"
#include "screens/screen_manager.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

PasswordGeneratedScreen::PasswordGeneratedScreen(ScreenManager *manager)
    : manager_(manager) {};

void PasswordGeneratedScreen::render() {
  std::string view_pw_art = R"(
+============================================+
|   PASSWORD GENERATION SCREEN               |
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

void PasswordGeneratedScreen::handle_input(char key) {
  if (key == 'b') {
    manager_->pop();
    std::cout << "\n[INFO] Returning to Home Pane...\n";
  }
}
