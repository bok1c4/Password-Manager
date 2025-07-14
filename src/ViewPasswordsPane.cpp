
#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>
#include "ViewPwPane.h"

class ViewPasswordsPane : public PaneInterface {
public:
    void render() override {
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

    void handle_input(char c) override {
        if (c == 'b') {
            std::cout << "\n[INFO] Returning to Home Pane...\n";
        }
    }
};