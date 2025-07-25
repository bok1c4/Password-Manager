#include "screens/password_generation_screen.h"
#include "config/config_manager.h"
#include "screens/note_input_screen.h"
#include "screens/password_generated_screen.h"
#include "screens/screen_manager.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

PasswordGenerationScreen::PasswordGenerationScreen(ScreenManager *manager,
                                                   AppConfig *config)
    : manager_(manager), config_(config) {}

void PasswordGenerationScreen::render() {
  std::string generate_pw_art = R"(
+============================================+
|           GENERATE NEW PASSWORD            |
+--------------------------------------------+
|  [Algorithm Used]: AES-256 Encryption      |
|                                            |
|   g) Generate New Password                 |
|                                            |
| [b] hack to Home                           |
+============================================+

Waiting for command: 
)";
  std::cout << generate_pw_art;
}

void PasswordGenerationScreen::handle_input(std::string key) {
  if (key == "g" || key == "G") {
    manager_->push(
        std::make_unique<PasswordGeneratedScreen>(manager_, config_));
  } else if (key == "\t") {
    // You can handle tab if needed
  } else if (key == "b" || key == "B") {
    std::cout << "\n[INFO] Returning to Home Pane...\n";
    manager_->pop();
  } else {
    std::cout << "[WARNING] Invalid command. Press 'g' to generate, 'b' to go "
                 "back.\n";
  }
}
