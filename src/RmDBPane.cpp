#include "RmDbPane.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

void RmDbPane::render() {
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

void RmDbPane::handle_input(char c) {
  if (c == 'b') {
    std::cout << "\n[INFO] Returning to Home Pane...\n";
  }
}
