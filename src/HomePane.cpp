// src/HomePane.cpp
#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>
#include "HomePane.h"

using namespace std::chrono_literals;

void HomePane::render() {
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

void HomePane::handle_input(char c) {
    if (c == 'q') {
        std::cout << "\n[INFO] Exiting program...\n";
        std::this_thread::sleep_for(2000ms);
        exit(0);
    }
}
