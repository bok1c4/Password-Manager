#include <iostream>
#include <thread>
#include <conio.h>
#include <chrono>
#include <cstdlib>

#include "HomePane.h"
#include "GenNewPw.h"
#include "ViewPwPane.h"
#include "AddDbPane.h"
#include "RmDbPane.h"

using namespace std::chrono_literals;

int main() {
    system("chcp 65001 > nul");

    HomePane home;
    GenerateNewPw gen;
    ViewPasswordsPane view;
    AddDatabasePane add;
    RemoveDatabasePane rm;

    PaneInterface* current = &home;

    while (true) {
        system("cls");
        current->render();

        char key = _getch();

        switch (key) {
            case '1': current = &gen; break;
            case '2': current = &view; break;
            case '3': current = &add; break;
            case '4': current = &rm; break;
            case 'b': current = &home; break;
            case 'q':
                std::cout << "\n[INFO] Quitting...\n";
                std::this_thread::sleep_for(1000ms);
                return 0;
        }

        current->handle_input(key);
        std::this_thread::sleep_for(800ms);
    }
}
