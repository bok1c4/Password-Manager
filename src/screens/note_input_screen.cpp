#include "screens/note_input_screen.h"
#include "../utils/terminal_utils.h"
#include "screens/screen_manager.h"

#include <iostream>
#include <string>
#include <thread>

using namespace std::chrono_literals;

NoteInputScreen::NoteInputScreen(ScreenManager *manager,
                                 const std::string &password)
    : manager_(manager), password_(password), note_("") {}

void NoteInputScreen::render() {
  std::cout << "\n+============================================+\n";
  std::cout << "|           ADD NOTE TO PASSWORD             |\n";
  std::cout << "+--------------------------------------------+\n";
  std::cout << "| Password: " << password_ << "\n";
  std::cout << "| Note: " << note_ << "\n";
  std::cout << "+--------------------------------------------+\n";
  std::cout << "| Type your note. Press Enter to save.       |\n";
  std::cout << "| Press ESC to cancel and go back.           |\n";
  std::cout << "+============================================+\n";
  std::cout << "\nWaiting for input: ";
}

void NoteInputScreen::handle_input(char key) {
  // ESC to cancel and go back
  if (key == 27) {
    std::cout << "\n[INFO] Going back to password screen...\n";
    manager_->pop();
    return;
  }

  if (key == '\n' || key == '\r') {
    std::cout << "\n[INFO] Note saved for password.\n";
    std::cout << "[DEBUG] Password: " << password_ << "\n";
    std::cout << "[DEBUG] Note: " << note_ << "\n";

    for (int i = 6; i >= 1; --i) {
      std::cout << "\rProceeding to save the credentials in database in " << i
                << "... " << std::flush;
      std::this_thread::sleep_for(1s);
    }

    std::cout << std::endl;
    std::cout << "Press Return (Enter) to confirm saving, or ESC to go back: "
              << std::flush;

    char confirm_key = getch(); // Blocking key read

    if (confirm_key == '\n' || confirm_key == '\r') {
      std::cout << "\n[INFO] Credentials confirmed and saved successfully!\n";
      // TODO: Save password_ + note_ to DB
      manager_->pop();
    } else if (confirm_key == 27) {
      std::cout
          << "\n[INFO] Operation cancelled. Returning to previous screen.\n";
      manager_->pop();
    } else {
      std::cout << "\n[WARNING] Unknown input. Returning to previous screen.\n";
      manager_->pop();
    }

    return;
  }

  // Backspace support
  if (key == 8 || key == 127) {
    if (!note_.empty()) {
      note_.pop_back();
    }
    return;
  }

  note_ += key;
}
