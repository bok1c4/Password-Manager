#include "screens/password_generation_screen.h"
#include "screens/note_input_screen.h"
#include "screens/password_generated_screen.h"
#include "screens/screen_manager.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

PasswordGenerationScreen::PasswordGenerationScreen(ScreenManager *manager)
    : manager_(manager) {}

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

void PasswordGenerationScreen::handle_input(char key) {
  switch (key) {
    // implement password generation
  case 'g':
    manager_->push(std::make_unique<PasswordGeneratedScreen>(manager_));
    break;
  case '\t':
    break;
  case 'b':
    std::cout << "\n[INFO] Returning to Home Pane...\n";
    manager_->pop(); // or replace if needed
    break;
  }
}
