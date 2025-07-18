#include "screens/password_view_screen.h"
#include "../utils/db_utils.h"
#include "config/config_manager.h"
#include "screens/screen_manager.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <thread>

PasswordViewScreen::PasswordViewScreen(ScreenManager *manager,
                                       AppConfig *config)
    : manager_(manager), config_(config) {}

void PasswordViewScreen::render() {
  auto entries = get_all_password_notes(config_->dbConnection);

  std::cout << "\n+============================================+\n";
  std::cout << "|             STORED PASSWORDS               |\n";
  std::cout << "+--------------------------------------------+\n";

  if (entries.empty()) {
    std::cout << "| No passwords saved in the database.        |\n";
  } else {
    for (const auto &[id, notes] : entries) {
      std::cout << "| ID: " << id << " | Note: " << notes << "\n";
    }
  }

  std::cout << "+--------------------------------------------+\n";
  std::cout << "| Enter an ID to view note, or [b] to go back|\n";
  std::cout << "+============================================+\n";
  std::cout << "Waiting for command: ";
}

void PasswordViewScreen::handle_input(std::string input) {
  if (input == "b" || input == "B") {
    std::cout << "\n[INFO] Returning to Home Pane...\n";
    manager_->pop();
    return;
  }

  try {
    int id = std::stoi(input);
    std::cout << "Pressed ID: " << id << "\n";

    auto [pw, note] = get_password_by_note_id(config_->dbConnection, id);

    if (!pw.empty()) {
      std::cout << "\n+============================================+\n";
      std::cout << "|          PASSWORD DETAILS (ID: " << id
                << ")           |\n";
      std::cout << "+--------------------------------------------+\n";
      std::cout << "| Password: " << pw << "\n";
      std::cout << "| Note:     " << note << "\n";
      std::cout << "+============================================+\n";
    } else {
      std::cout << "\n[WARNING] No entry found for ID " << id << "\n";
    }
  } catch (const std::exception &e) {
    std::cout << "\n[ERROR] Invalid input. Please enter a numeric ID or 'b' to "
                 "go back.\n";
  }

  std::cout << "Press any key to go back...";
  std::cin.get();
  manager_->pop();
}
