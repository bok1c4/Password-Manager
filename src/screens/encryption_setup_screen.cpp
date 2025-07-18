#include "screens/encryption_setup_screen.h"
#include "../utils/crypto.h"
#include "../utils/db_utils.h"
#include "config/config_manager.h"
#include "screens/screen_manager.h"
#include <chrono>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

EncryptionSetupScreen::EncryptionSetupScreen(ScreenManager *manager,
                                             AppConfig *config)
    : manager_(manager), config_(config) {}

void EncryptionSetupScreen::render() {
  std::string art = R"(
+============================================+
|              ENCRYPTION SETUP              |
+--------------------------------------------+
|                                            |
|  Current Private Key Loaded:                  
|    )" + config_->privateKey.username +
                    R"(        
|                                            
|  Current Public Keys Loaded:                | 
)";

  std::cout << art;

  for (const auto &pubKey : config_->publicKeys) {
    std::cout << "    - " << pubKey.username << "\n";
  }

  std::cout << R"(
|                                            
|  [p] Change Private Key Path                
|  [u] Add Public Key Path                     
|  [r] Reset Keys to Default                   
|                                            
|  [b] Back to Home                           |
+============================================+

Waiting for command: 
)";
}

void EncryptionSetupScreen::handle_input(std::string key) {
  if (key == "b") {
    std::cout << "\n[INFO] Returning to Home Pane...\n";
    manager_->pop();
    return;
  }

  if (key == "p") {
    std::string newPrivPath;
    std::cout << "Enter new private key path:\n> ";
    std::getline(std::cin, newPrivPath);

    std::string machineName;
    std::cout << "Enter username/machine name for private key:\n> ";
    std::getline(std::cin, machineName);

    config_->privateKey = {newPrivPath, machineName, ""};

    // Try to match username from existing public keys based on private key
    auto maybeUsername = Encryptor::match_username_from_public_keys(
        newPrivPath, config_->publicKeys);
    if (maybeUsername.has_value()) {
      std::cout << "[INFO] Private key matches public key username: "
                << maybeUsername.value() << "\n";
      // Override username with matched username for consistency
      config_->privateKey.username = maybeUsername.value();
    } else {
      std::cout
          << "[INFO] No matching public key found for this private key.\n";
    }

    ConfigManager configManager("config.json");
    if (!configManager.load()) {
      std::cerr << "[ERROR] Failed to load config.json.\n";
      return;
    }

    configManager.getConfig().privateKey = config_->privateKey;

    if (configManager.save()) {
      std::cout << "[INFO] ✅ Private key path and username updated.\n";
    } else {
      std::cerr << "[ERROR] ❌ Failed to save config.json.\n";
    }

    std::this_thread::sleep_for(2s);
    return;
  }

  if (key == "u") {
    std::string newPubPath;
    std::cout << "Enter new public key path to add:\n> ";
    std::getline(std::cin, newPubPath);

    std::string pubUsername;
    std::cout << "Enter username/machine name for this public key:\n> ";
    std::getline(std::cin, pubUsername);

    std::string fingerprint =
        Encryptor::get_fingerprint_from_pubkey(newPubPath);
    if (fingerprint.empty()) {
      std::cerr << "[ERROR] Could not extract fingerprint from public key.\n";
      return;
    }

    std::string keyData =
        Encryptor::printPublicKeyInfoAndReturnContent(newPubPath);
    if (keyData.empty()) {
      std::cerr << "[ERROR] Could not parse or read the key.\n";
      return;
    }

    if (!test_db_conn(config_->dbConnection)) {
      std::cerr
          << "Could not connect to the database, please check your URI.\n";
      return;
    }

    auto foundUser = find_user_by_key_or_username(config_->dbConnection,
                                                  keyData, pubUsername);

    if (foundUser.has_value()) {
      std::cout << "[INFO] User or key already exists in DB with username: "
                << foundUser.value() << "\n";
    } else {
      // Save with fingerprint included
      if (!save_public_key_ref(config_->dbConnection, keyData, fingerprint,
                               pubUsername)) {
        std::cerr << "[ERROR] Failed to save public key to DB.\n";
        return;
      }
      std::cout << "[INFO] Public key saved to database successfully.\n";
    }

    KeyReference pubKeyRef{newPubPath, pubUsername, fingerprint};

    bool exists = false;
    for (const auto &kr : config_->publicKeys) {
      if (kr.path == newPubPath && kr.username == pubUsername) {
        exists = true;
        break;
      }
    }
    if (!exists) {
      config_->publicKeys.push_back(pubKeyRef);
    }

    ConfigManager configManager("config.json");
    if (!configManager.load()) {
      std::cerr << "[ERROR] Failed to load config.json.\n";
      return;
    }

    configManager.getConfig().publicKeys = config_->publicKeys;

    if (configManager.save()) {
      std::cout << "[INFO] Config file updated with public keys.\n";
    } else {
      std::cerr << "[ERROR] Failed to save config.\n";
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));
    return;
  }

  if (key == "r") {
    KeyReference defaultPriv = {"/home/you/.keys/private.asc",
                                "default-machine", ""};
    std::vector<KeyReference> defaultPubs = {
        {"/home/you/.keys/public.asc", "default-machine", ""}};

    config_->privateKey = defaultPriv;
    config_->publicKeys = defaultPubs;

    ConfigManager configManager("config.json");
    if (!configManager.load()) {
      std::cerr << "[ERROR] Failed to load config.json.\n";
      return;
    }

    configManager.getConfig().privateKey = defaultPriv;
    configManager.getConfig().publicKeys = defaultPubs;

    if (configManager.save()) {
      std::cout << "[INFO] Key paths reset to defaults.\n";
    } else {
      std::cerr << "[ERROR] Failed to save config.\n";
    }

    std::this_thread::sleep_for(2s);
    return;
  }

  std::cout << "[INFO] Invalid input. Please try again.\n";
  std::this_thread::sleep_for(2s);
}
