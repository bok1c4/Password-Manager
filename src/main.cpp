#include <chrono>
#include <cstdlib>
#include <iostream>
#include <termios.h>
#include <thread>
#include <unistd.h>

#include "AddDbPane.h"
#include "GenNewPw.h"
#include "HomePane.h"
#include "RmDbPane.h"
#include "ViewPwPane.h"

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
  // UTF-8 support generally already default in Linux terminal
  // system("chcp 65001 > nul"); <-- REMOVE

  HomePane home;
  GenNewPw gen;
  ViewPwPane view;
  AddDbPane add;
  RmDbPane rm;

  PaneInterface *current = &home;

  while (true) {
    clear_screen();
    current->render();

    char key = getch();

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
