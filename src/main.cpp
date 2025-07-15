#include <chrono>
#include <iostream>
#include <thread>

#include "utils/terminal_utils.h"

#include "add_database_screen.h"
#include "main_menu_screen.h"
#include "password_generation_screen.h"
#include "password_view_screen.h"
#include "remove_database_screen.h"

using namespace std::chrono_literals;

int main() {
  MainMenuScreen home;
  PasswordGenerationScreen gen;
  PasswordViewScreen view;
  AddDatabaseScreen add;
  RemoveDatabaseScreen rm;

  PaneInterface *current = &home;

  while (true) {
    clear_screen();
    current->render();

    char key = getch();

    std::cout << "Pressed: " << key << std::endl;

    switch (key) {
    case '1':
      current = &gen;
      break;
    case '2':
      current = &view;
      break;
    case '3':
      current = &add;
      break;
    case '4':
      current = &rm;
      break;
    case 'b':
      current = &home;
      break;
    case 'q':
      std::cout << "\n[INFO] Quitting...\n";
      std::this_thread::sleep_for(1000ms);
      return 0;
    }

    current->handle_input(key);
    std::this_thread::sleep_for(800ms);
  }
}
