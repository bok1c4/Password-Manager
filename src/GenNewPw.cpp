#include "GenNewPw.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

void GenNewPw::render() {
  std::string generate_pw_art = R"(
+============================================+
|           GENERATE NEW PASSWORD            |
+--------------------------------------------+
|  [Algorithm Used]: AES-256 Encryption      |
|                                            |
|  Enter New Password: ____________________  |
|                                            |
|  Optional Note: _________________________  |
|                                            |
|  [b] Back to Home                          |
+============================================+

Waiting for command: 
)";
  std::cout << generate_pw_art;
}

void GenNewPw::handle_input(char c) {
  if (c == 'b') {
    std::cout << "\n[INFO] Returning to Home Pane...\n";
  }
}
