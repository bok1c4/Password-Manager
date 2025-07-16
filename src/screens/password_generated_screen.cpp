#include "screens/password_generated_screen.h"
#include "screens/note_input_screen.h"
#include "screens/screen_manager.h"

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>

PasswordGeneratedScreen::PasswordGeneratedScreen(ScreenManager *manager)
    : password(generate_random_string()), manager_(manager) {}

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

void PasswordGeneratedScreen::handle_input(char key) {
  switch (key) {
  case 'b':
    manager_->pop();
    std::cout << "\n[INFO] Returning to Home Pane...\n";
    break;

  case 'n':

    // NoteInputScreen needs to have access to password
    // so when note is provided it can be saved in the database
    // Also later NoteInputScreen should also be provided with db connection to
    // run sql scripts
    manager_->push(std::make_unique<NoteInputScreen>(manager_, password));
    break;

  default:
    break;
  }
}
