#include <chrono>
#include <cstdlib>
#include <iostream>
#include <termios.h>
#include <thread>
#include <unistd.h>

#include "add_database_screen.h"
#include "main_menu_screen.h"
#include "password_generation_screen.h"
#include "password_view_screen.h"
#include "remove_database_screen.h"

using namespace std::chrono_literals;

// === Replacement for _getch() on Linux ===
char getch() {
  char buf = 0;
  struct termios old{};
  if (tcgetattr(STDIN_FILENO, &old) < 0)
    perror("tcgetattr()");

  struct termios newt = old;
  newt.c_lflag &= ~(ICANON | ECHO);
  if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) < 0)
    perror("tcsetattr()");

  if (read(STDIN_FILENO, &buf, 1) < 0)
    perror("read()");

  if (tcsetattr(STDIN_FILENO, TCSADRAIN, &old) < 0)
    perror("tcsetattr()");

  return buf;
}

// === Clear screen using ANSI escape codes ===
void clear_screen() { std::cout << "\033[2J\033[1;1H"; }

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

      // case in here for pw_gen panel?
      // To change current rendering

    case 'q':
      std::cout << "\n[INFO] Quitting...\n";
      std::this_thread::sleep_for(1000ms);
      return 0;
    }

    current->handle_input(key);
    std::this_thread::sleep_for(800ms);
  }
}
