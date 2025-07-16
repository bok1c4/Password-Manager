#include <iostream>
#include <thread>

#include "screens/main_menu_screen.h"
#include "screens/screen_manager.h"
#include "utils/terminal_utils.h"

#include "screens/note_input_screen.h"
#include "screens/password_generation_screen.h"

using namespace std::chrono_literals;

int main() {
  ScreenManager screen_manager;

  screen_manager.push(std::make_unique<MainMenuScreen>(&screen_manager));

  while (!screen_manager.empty()) {
    clear_screen();

    PaneInterface *current = screen_manager.current();
    if (!current)
      break;

    current->render();
    char key = getch();
    std::cout << "Command pressed: " << key << std::endl;
    current->handle_input(key);
    std::this_thread::sleep_for(500ms);
  }

  std::cout << "\n[INFO] Quitting...\n";
  return 0;
}
