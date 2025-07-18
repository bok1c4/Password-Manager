#include <iostream>
#include <thread>

#include "config/config_manager.h"
#include "screens/main_menu_screen.h"
#include "screens/screen_manager.h"
#include "utils/terminal_utils.h"

#include "screens/password_generation_screen.h"

using namespace std::chrono_literals;

int main() {
  ConfigManager configManager("config.json");
  if (!configManager.load()) {
    std::cerr << "[FATAL] Could not load or create config.json\n";
    return 1;
  }

  AppConfig config = configManager.getConfig();

  // config output
  std::cout << "[DEBUG] DB: " << config.dbConnection << "\n";
  std::cout << "[DEBUG] Private Key: " << config.privateKeyPath << "\n";
  std::cout << "[DEBUG] Public Keys:\n";
  for (const auto &key : config.publicKeys)
    std::cout << "  - " << key << "\n";

  ScreenManager screen_manager;

  screen_manager.push(
      std::make_unique<MainMenuScreen>(&screen_manager, &config));

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
