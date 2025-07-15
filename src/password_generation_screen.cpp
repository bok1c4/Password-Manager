#include "password_generation_screen.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

void PasswordGeneretionScreen::render() {
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

void PasswordGeneretionScreen::handle_input(char c) {

  // switch case
  // and redirecting to other panes

  if (c == 'b') {
    std::cout << "\n[INFO] Returning to Home Pane...\n";
  }
}
