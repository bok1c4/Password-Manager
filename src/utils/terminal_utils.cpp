#include "terminal_utils.h"
#include <iostream>
#include <termios.h>
#include <unistd.h>

// Replacement for _getch() on Linux
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

// Clear screen using ANSI escape codes
void clear_screen() { std::cout << "\033[2J\033[1;1H"; }
