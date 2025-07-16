#include "./screens/add_database_screen.h"
#include "screens/screen_manager.h"
#include <chrono>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

AddDatabaseScreen::AddDatabaseScreen(ScreenManager *manager)
    : manager_(manager) {}

void AddDatabaseScreen::render() {
  std::string add_db_art = R"(
+============================================+
|              ADD DATABASE FILE             |
+--------------------------------------------+
|  Path to DB File: _______________________  |
|                                            |
|  The file will be used for storing creds   |
|                                            |
|  [b] Back to Home                          |
+============================================+

Waiting for command: 
)";
  std::cout << add_db_art;
}

void AddDatabaseScreen::handle_input(char key) {
  if (key == 'b') {
    std::cout << "\n[INFO] Returning to Home Pane...\n";
    manager_->pop();
  }
}
