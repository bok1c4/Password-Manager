#include "screens/password_generated_screen.h"
#include "config/config_manager.h"
#include "screens/note_input_screen.h"
#include "screens/screen_manager.h"

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>

using std::string;

PasswordGeneratedScreen::PasswordGeneratedScreen(ScreenManager *manager,
                                                 AppConfig *config)
    : password(generate_random_string()), config_(config), manager_(manager) {}

std::string
PasswordGeneratedScreen::generate_random_string(const size_t length) {
  const std::string characters = "0123456789"
                                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "abcdefghijklmnopqrstuvwxyz"
                                 "!@#$%^&*()-_=+[]{}|;:,.<>?/~`";

  std::random_device random_device;
  std::mt19937 generator(random_device());
  std::uniform_int_distribution<> distribution(0, characters.size() - 1);

  std::string random_string;
  for (size_t i = 0; i < length; ++i) {
    random_string += characters[distribution(generator)];
  }

  return random_string;
}

void PasswordGeneratedScreen::render() {
  std::ostringstream password_line;
  password_line << "|  Password: " << std::setw(40) << std::left << password
                << "\n";

  std::string view_pw_art = "+============================================+\n"
                            "| GENERATED PASSWORD WITH NOTE               |\n"
                            "+--------------------------------------------+\n" +
                            password_line.str() +
                            "|                                            |\n"
                            "|  n) add note                               |\n"
                            "|                                            |\n"
                            "|  [b] Back to Home                          |\n"
                            "+============================================+\n\n"
                            "Waiting for command: ";

  std::cout << view_pw_art;
}

void PasswordGeneratedScreen::handle_input(std::string key) {
  if (key == "b" || key == "B") {
    manager_->pop();
    std::cout << "\n[INFO] Returning to Home Pane...\n";
  } else if (key == "n" || key == "N") {
    manager_->push(
        std::make_unique<NoteInputScreen>(manager_, password, config_));
  } else {
    std::cout << "[WARNING] Invalid command. Press 'b' to go back or 'n' to "
                 "add a note.\n";
  }
}
