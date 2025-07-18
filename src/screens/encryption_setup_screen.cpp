#include "screens/encryption_setup_screen.h"
#include "config/config_manager.h"
#include "screens/screen_manager.h"
#include <chrono>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

// So for user to provide public key
// I need to have valid db connection
// store the pk in database and link it to the user provided
//
// When user provides the public key to the CLI TOOL,
// besides the pk path, user needs to provide some kind of username
// which will reference the machine where the public key is used
//
// So when user provides pk with username
// check if its already in config.json and db
//
// in config.json we should also provide the username
// and to display the data on the screen

EncryptionSetupScreen::EncryptionSetupScreen(ScreenManager *manager,
                                             AppConfig *config)
    : manager_(manager), config_(config) {}

void EncryptionSetupScreen::render() {
  std::string art = R"(
+============================================+
|              ENCRYPTION SETUP              |
+--------------------------------------------+
|                                            |
|  Current Private Key Path:                  
|    )" + config_->privateKeyPath +
                    R"(        
|                                            
|  Current Public Keys Paths:                 
)";

  std::cout << art;

  for (const auto &pubKey : config_->publicKeys) {
    std::cout << "    - " << pubKey << "\n";
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

    config_->privateKeyPath = newPrivPath;

    ConfigManager configManager("config.json");
    if (!configManager.load()) {
      std::cerr << "[ERROR] Failed to load config.json.\n";
      return;
    }
    configManager.getConfig().privateKeyPath = newPrivPath;

    if (configManager.save()) {
      std::cout << "[INFO] Private key path updated successfully.\n";
    } else {
      std::cerr << "[ERROR] Failed to save config.\n";
    }
    std::this_thread::sleep_for(2s);
    return;
  }

  if (key == "u") {
    std::string newPubPath;
    std::cout << "Enter new public key path to add:\n> ";
    std::getline(std::cin, newPubPath);

    // Add new public key path to vector
    config_->publicKeys.push_back(newPubPath);

    ConfigManager configManager("config.json");
    if (!configManager.load()) {
      std::cerr << "[ERROR] Failed to load config.json.\n";
      return;
    }
    configManager.getConfig().publicKeys.push_back(newPubPath);

    if (configManager.save()) {
      std::cout << "[INFO] Public key path added successfully.\n";
    } else {
      std::cerr << "[ERROR] Failed to save config.\n";
    }
    std::this_thread::sleep_for(2s);
    return;
  }

  if (key == "r") {
    // Reset to some sensible default paths
    std::string defaultPriv = "/home/you/.keys/private.asc";
    std::vector<std::string> defaultPubs = {"/home/you/.keys/public.asc"};

    config_->privateKeyPath = defaultPriv;
    config_->publicKeys = defaultPubs;

    ConfigManager configManager("config.json");
    if (!configManager.load()) {
      std::cerr << "[ERROR] Failed to load config.json.\n";
      return;
    }
    configManager.getConfig().privateKeyPath = defaultPriv;
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
