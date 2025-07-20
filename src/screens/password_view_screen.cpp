#include "screens/password_view_screen.h"
#include "../utils/crypto.h"
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

  std::cout << "\n+==========================================+\n";
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
  std::cout << "|        Enter an ID to manage the entry     |\n";
  std::cout << "|             or [b] to go back              |\n";
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

    auto [pwEnc, note, aes_key_enc] =
        get_password_by_note_id(config_->dbConnection, id);

    if (!pwEnc.empty()) {
      std::cout << "\n+============================================+\n";
      std::cout << "|          PASSWORD DETAILS (ID: " << id
                << ")           |\n";
      std::cout << "+--------------------------------------------+\n";
      std::cout << "| [s] Show decrypted password                |\n";
      std::cout << "| [e] Edit password                          |\n";
      std::cout << "| [b] Back                                   |\n";
      std::cout << "+============================================+\n";
      std::cout << "Choice: ";

      std::string choice;
      std::getline(std::cin, choice);

      Encryptor enc(config_);

      if (choice == "s" || choice == "S") {
        try {
          std::string password = enc.decrypt_hybrid(pwEnc, aes_key_enc);
          if (password.empty()) {
            std::cerr << "[ERROR] Failed to decrypt password.\n";
          } else {
            std::cout << "\n[DECRYPTED PASSWORD]: " << password << "\n";
          }
        } catch (const std::exception &e) {
          std::cerr << "[ERROR] Decryption failed: " << e.what() << "\n";
        }
      } else if (choice == "e" || choice == "E") {
        std::cout << "[INFO] Password editing is not yet implemented.\n";
        std::cout << "[INFO] Going back...\n";
      } else if (choice == "b" || choice == "B") {
        std::cout << "[INFO] Going back...\n";
      } else {
        std::cout << "[WARNING] Invalid choice.\n";
      }

    } else {
      std::cout << "\n[WARNING] No entry found for ID " << id << "\n";
    }
  } catch (const std::exception &e) {
    std::cout << "\n[ERROR] Invalid input. Please enter a numeric ID or 'b' to "
                 "go back.\n";
  }

  std::cout << "Press ENTER to go back...";
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  manager_->pop();
}
