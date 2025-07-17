#include "screens/note_input_screen.h"
#include "../utils/db_utils.h"
#include "../utils/terminal_utils.h"
#include "screens/screen_manager.h"

#include <fstream>
#include <iostream>
#include <string>
#include <thread>

using std::string;

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

void NoteInputScreen::handle_input(std::string key) {
  // Handle ESC input (ASCII 27) typed as string — unlikely, but you can map
  // "ESC" as a string
  if (key ==
      "ESC") { // Optional: you'd have to map this manually in getch-based logic
    std::cout << "\n[INFO] Going back to password screen...\n";
    manager_->pop();
    return;
  }

  // Handle Enter (user presses enter, so input is empty string)
  if (key.empty()) {
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

    char confirm_key = getch(); // Here you can keep getch() for key press

    if (confirm_key == '\n' || confirm_key == '\r') {
      bool isSaved = save_to_db(password_, note_);
      if (isSaved) {
        std::cout << "\n[INFO] Credentials confirmed and saved successfully!\n";
      } else {
        std::cerr << "\n[ERROR] Failed to save credentials to the database.\n";

        std::ofstream log("db_errors.log", std::ios::app);
        if (log.is_open()) {
          log << "[ERROR] Failed to save note for password: " << password_
              << "\n";
          log.close();
        }
      }
      manager_->pop();
    } else if (confirm_key == 27) { // ESC
      std::cout
          << "\n[INFO] Operation cancelled. Returning to previous screen.\n";
      manager_->pop();
    } else {
      std::cout << "\n[WARNING] Unknown input. Returning to previous screen.\n";
      manager_->pop();
    }
    return;
  }

  // Handle Backspace
  if (key == "\b" || key[0] == 127 || key[0] == 8) {
    if (!note_.empty()) {
      note_.pop_back();
    }
    return;
  }

  // Accept character input
  note_ += key;
}
