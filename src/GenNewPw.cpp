#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>
#include "GenNewPw.h"

using namespace std::chrono_literals;

class GenNewPw : public PaneInterface {
public:
    void render() override {
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

    void handle_input(char c) override {
        if (c == 'b') {
            std::cout << "\n[INFO] Returning to Home Pane...\n";
        }
    }
};
