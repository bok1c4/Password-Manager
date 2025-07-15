// src/HomePane.cpp
#include "main_menu_screen.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

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

void MainMenuScreen::handle_input(char c) {
  if (c == 'q') {
    std::cout << "\n[INFO] Exiting program...\n";
    std::this_thread::sleep_for(2000ms);
    exit(0);
  }
}
