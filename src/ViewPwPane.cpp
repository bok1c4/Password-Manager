
#include "ViewPwPane.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

void ViewPwPane::render() {
  std::string view_pw_art = R"(
+============================================+
|             STORED PASSWORDS               |
+--------------------------------------------+
|  [List of Saved Password Entries]          |
|                                            |
|  Use ID or keyword to view specific entry  |
|                                            |
|  [b] Back to Home                          |
+============================================+

Waiting for command: 
)";
  std::cout << view_pw_art;
}

void ViewPwPane::handle_input(char c) {
  if (c == 'b') {
    std::cout << "\n[INFO] Returning to Home Pane...\n";
  }
}
