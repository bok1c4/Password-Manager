#include "screens/main_menu_screen.h"
#include "screens/add_database_screen.h"
#include "screens/password_generation_screen.h"
#include "screens/password_view_screen.h"
#include "screens/remove_database_screen.h"
#include "screens/screen_manager.h"

#include <iostream>
#include <memory>
#include <thread>

using std::string;

using namespace std::chrono_literals;

MainMenuScreen::MainMenuScreen(ScreenManager *manager) : manager_(manager) {}

void MainMenuScreen::render() {
  std::string art = R"(
+============================================+
|         PASSWORD MANAGER CLI TOOL          |
+--------------------------------------------+
|  [1] Generate New Password                 |
|  [2] View Stored Passwords                 |
|  [3] Manage Database                       |
|  [4] Key Sharing & Encryption Setup        |
|  [q] Quit                                  |
+============================================+

Waiting for command: 
)";
  std::cout << art;
}

void MainMenuScreen::handle_input(std::string key) {
  if (key == "1") {
    manager_->push(std::make_unique<PasswordGenerationScreen>(manager_));
  } else if (key == "2") {
    manager_->push(std::make_unique<PasswordViewScreen>(manager_));
  } else if (key == "3") {
    manager_->push(std::make_unique<AddDatabaseScreen>(manager_));
  } else if (key == "4") {
    manager_->push(std::make_unique<RemoveDatabaseScreen>(manager_));
  } else if (key == "q" || key == "Q") {
    std::cout << "\n[INFO] Exiting program...\n";
    std::this_thread::sleep_for(2000ms);
    exit(0);
  } else {
    std::cout << "\n[WARNING] Invalid input. Please choose a valid option.\n";
  }
}
