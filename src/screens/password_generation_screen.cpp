#include "./screens/password_generation_screen.h"
#include "./screens/password_input_screen.h"
#include "./screens/screen_manager.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

void PasswordGenerationScreen::render() {
  std::string generate_pw_art = R"(
+============================================+
|           GENERATE NEW PASSWORD            |
+--------------------------------------------+
|  [Algorithm Used]: AES-256 Encryption      |
|                                            |
|  p) Enter New Password: __________________ |
|                                            |
|  n) Optional Note: _______________________ |
|                                            |
| [b] hack to Home                           |
+============================================+

Waiting for command: 
)";
  std::cout << generate_pw_art;
}

void PasswordGenerationScreen::handle_input(char key) {
  switch (key) {
  case 'p':
    manager_->push(std::make_unique<PasswordInputScreen>(manager_));
    break;
  case 'n':
    break;
  case '\t':
    break;
  case 'b':
    std::cout << "\n[INFO] Returning to Home Pane...\n";
    manager_->pop(); // or replace if needed
    break;
  }
}
