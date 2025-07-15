#include <AddDbPane.h>
#include <chrono>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

void AddDbPane::render() {
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

void AddDbPane ::handle_input(char c) {
  if (c == 'b') {
    std::cout << "\n[INFO] Returning to Home Pane...\n";
  }
};
