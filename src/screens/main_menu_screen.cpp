#include "./screens/main_menu_screen.h"
#include "./screens/add_database_screen.h"
#include "./screens/password_generation_screen.h"
#include "./screens/password_view_screen.h"
#include "./screens/remove_database_screen.h"
#include "./screens/screen_manager.h"

#include <iostream>
#include <memory>
#include <thread>

using namespace std::chrono_literals;

MainMenuScreen::MainMenuScreen(ScreenManager *manager) : manager_(manager) {}

void MainMenuScreen::render() {
  std::string art = R"(
+============================================+
|         PASSWORD MANAGER CLI TOOL          |
+--------------------------------------------+
|  [1] Generate New Password                 |
|  [2] View Stored Passwords                 |
|  [3] Add Database                          |
|  [4] Remove Database                       |
|  [q] Quit                                  |
+============================================+

Waiting for command: 
)";
  std::cout << art;
}

void MainMenuScreen::handle_input(char key) {
  switch (key) {
  case '1':
    manager_->push(std::make_unique<PasswordGenerationScreen>(manager_));
    break;
  case '2':
    manager_->push(std::make_unique<PasswordViewScreen>(manager_));
    break;
  case '3':
    manager_->push(std::make_unique<AddDatabaseScreen>(manager_));
    break;
  case '4':
    manager_->push(std::make_unique<RemoveDatabaseScreen>(manager_));
    break;
  case 'q':
    std::cout << "\n[INFO] Exiting program...\n";
    std::this_thread::sleep_for(2000ms);
    exit(0);
  default:
    break;
  }
}
