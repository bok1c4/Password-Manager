#include "./screens/remove_database_screen.h"
#include "screens/screen_manager.h"
#include <chrono>
#include <cstdlib>
#include <iostream>

using namespace std::chrono_literals;

RemoveDatabaseScreen::RemoveDatabaseScreen(ScreenManager *manager)
    : manager_(manager) {};

void RemoveDatabaseScreen::render() {
  std::string remove_db_art = R"(
+============================================+
|            REMOVE DATABASE ENTRY           |
+--------------------------------------------+
|  DB File/ID to Remove: _________________   |
|                                            |
|  WARNING: This will delete all contents    |
|                                            |
|  [b] Back to Home                          |
+============================================+

Waiting for command: 
)";
  std::cout << remove_db_art;
}

void RemoveDatabaseScreen::handle_input(char key) {
  if (key == 'b') {
    manager_->pop();
    std::cout << "\n[INFO] Returning to Home Pane...\n";
  }
}
