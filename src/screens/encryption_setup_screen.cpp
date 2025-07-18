#include "screens/encryption_setup_screen.h"
#include "screens/screen_manager.h"
#include <chrono>
#include <cstdlib>
#include <iostream>

using namespace std::chrono_literals;

EncryptionSetupScreen::EncryptionSetupScreen(ScreenManager *manager)
    : manager_(manager) {};

void EncryptionSetupScreen::render() {
  std::string remove_db_art = R"(
+============================================+
|              ENCRYPTION SETUP              |
+--------------------------------------------+
|                                            |
|                                            |
|                                            |
|                                            |
|  [b] Back to Home                          |
+============================================+

Waiting for command: 
)";
  std::cout << remove_db_art;
}

// Display current path from config.json
// if key == "c"
// Then user needs to provide valid url and then use that db connection
// for database operations like in db_utils.cpp
// so we need to change instead of traversing trough .json everytime just
// to init the connnection with database, if successful we have db value
// which we can use to run sql scripts to insert update or retrieve data

void EncryptionSetupScreen::handle_input(std::string key) {
  if (key == "b") {
    manager_->pop();
    std::cout << "\n[INFO] Returning to Home Pane...\n";
  }
}
