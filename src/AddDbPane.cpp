#include <chrono>
#include <iostream>
#include <thread>
#include <conio.h> // For _getch on Windows
#include <AddDbPane.h>

using namespace std::chrono_literals;

class AddDbPane : public PaneInterface {
public:
    void render() override {
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

    void handle_input(char c) override {
        if (c == 'b') {
            std::cout << "\n[INFO] Returning to Home Pane...\n";
        }
    }
};