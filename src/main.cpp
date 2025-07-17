#include <iostream>
#include <thread>

#include "screens/main_menu_screen.h"
#include "screens/screen_manager.h"
#include "utils/terminal_utils.h"
#include <dotenv-cpp/include/laserpants/dotenv/dotenv.h>

#include "screens/note_input_screen.h"
#include "screens/password_generation_screen.h"

using namespace std::chrono_literals;

int main() {
  dotenv::init("../.env");
  ScreenManager screen_manager;

  screen_manager.push(std::make_unique<MainMenuScreen>(&screen_manager));

  while (!screen_manager.empty()) {
    PaneInterface *current = screen_manager.current();
    if (!current)
      break;

    current->render();

    std::string input;
    std::getline(std::cin, input);
    current->handle_input(input);

    clear_screen();
  }

  std::cout << "\n[INFO] Quitting...\n";
  return 0;
}
