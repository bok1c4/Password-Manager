#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>
#include "RmDbPane.h"

using namespace std::chrono_literals;

class RmDbPane : public PaneInterface {
public:
    void render() override {
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

    void handle_input(char c) override {
        if (c == 'b') {
            std::cout << "\n[INFO] Returning to Home Pane...\n";
        }
    }
};