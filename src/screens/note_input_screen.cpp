#include "screens/note_input_screen.h"
#include "../utils/crypto.h"
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
                                 const std::string &password, AppConfig *config)
    : manager_(manager), password_(password), note_(""), config_(config) {}

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
  // Cancel and go back on ESC
  if (key == "ESC") {
    std::cout << "\n[INFO] Going back to password screen...\n";
    manager_->pop();
    return;
  }

  // Handle Backspace (common codes: "\b", ASCII 127 or 8)
  if (key == "\b" || (key.size() == 1 && (key[0] == 127 || key[0] == 8))) {
    if (!note_.empty()) {
      note_.pop_back();
    }
    return;
  }

  // Handle Enter key (empty string here means user pressed Enter)
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

    char confirm_key = getch();

    if (confirm_key == '\n' || confirm_key == '\r') {
      try {
        // 1. Generate AES key (32 bytes)
        std::string aes_key = Encryptor::generate_aes_key();

        // 2. Encrypt password with AES key
        std::string encrypted_password =
            Encryptor::aes_encrypt_password(password_, aes_key);

        // 3. Encrypt AES key with recipient public keys (hybrid encryption)
        auto encryptedAesKey =
            Encryptor::encrypt_passwords_with_pks(aes_key, config_->publicKeys);
        if (encryptedAesKey.encryptedPasswords.empty()) {
          std::cerr << "[ERROR] Failed to encrypt AES key with public keys.\n";
          return;
        }

        // 4. Save encrypted password, encrypted AES key(s), and note
        // (plaintext)
        bool isSaved = save_to_db(config_->dbConnection, encrypted_password,
                                  encryptedAesKey.encryptedPasswords, note_);

        if (isSaved) {
          std::cout
              << "\n[INFO] Credentials confirmed and saved successfully!\n";
        } else {
          std::cerr
              << "\n[ERROR] Failed to save credentials to the database.\n";
          std::ofstream log("db_errors.log", std::ios::app);
          if (log.is_open()) {
            log << "[ERROR] Failed to save encrypted note for password: "
                << password_ << "\n";
            log.close();
          }
        }
      } catch (const std::exception &ex) {
        std::cerr << "[EXCEPTION] " << ex.what() << "\n";
      }

      manager_->pop();
      return;
    } else if (confirm_key == 27) { // ESC to cancel on confirmation prompt
      std::cout
          << "\n[INFO] Operation cancelled. Returning to previous screen.\n";
      manager_->pop();
      return;
    } else {
      std::cout << "\n[WARNING] Unknown input. Returning to previous screen.\n";
      manager_->pop();
      return;
    }
  }

  // Normal character input: append to note
  note_ += key;
}
