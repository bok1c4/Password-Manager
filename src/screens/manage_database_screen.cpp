#include "screens/manage_database_screen.h"
#include "config/config_manager.h"
#include "screens/screen_manager.h"
#include <chrono>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

ManageDatabaseScreen::ManageDatabaseScreen(ScreenManager *manager,
                                           AppConfig *config)
    : manager_(manager), config_(config) {}

void ManageDatabaseScreen::render() {
  std::string art = R"(
+============================================+
|           MANAGE YOUR DATABASE             |
+--------------------------------------------+
|                                            |
|  [a] Add or Update DB Connection           |
|  [r] Reset DB Connection to Default        |
|                                            |
|  [b] Back to Home                          |
+--------------------------------------------+
| Format: postgres://user:pass@host:port/db  |
+============================================+

Waiting for command: 
)";
  std::cout << art;
}

void ManageDatabaseScreen::handle_input(std::string key) {
  if (key == "b") {
    std::cout << "\n[INFO] Returning to Home Pane...\n";
    manager_->pop();
    return;
  }

  if (key == "a") {
    std::string newConn;
    std::cout << "\nEnter new DB connection string:\n> ";
    std::getline(std::cin, newConn);

    bool isJdbc = newConn.find("jdbc:postgresql://") == 0;
    bool isUri = newConn.find("postgres://") == 0;

    if (!isJdbc && !isUri) {
      std::cout << "[WARNING] Invalid format. Must start with 'postgres://' or "
                   "'jdbc:postgresql://'\n";
      std::this_thread::sleep_for(2s);
      return;
    }

    std::string finalConn;

    if (isJdbc) {
      // Strip prefix
      std::string stripped =
          newConn.substr(std::string("jdbc:postgresql://").size());

      // Format: host:port/dbname
      size_t slash = stripped.find('/');
      size_t colon = stripped.find(':');

      if (colon == std::string::npos || slash == std::string::npos ||
          slash < colon) {
        std::cout << "[ERROR] Invalid JDBC format. Expected host:port/dbname\n";
        std::this_thread::sleep_for(2s);
        return;
      }

      std::string host = stripped.substr(0, colon);
      std::string port = stripped.substr(colon + 1, slash - colon - 1);
      std::string dbname = stripped.substr(slash + 1);

      std::string user, password;
      std::cout << "Enter database username: ";
      std::getline(std::cin, user);
      std::cout << "Enter password for user '" << user << "': ";
      std::getline(std::cin, password);

      finalConn = "host=" + host + " port=" + port + " dbname=" + dbname +
                  " user=" + user + " password=" + password;
    } else {
      // User provided full postgres://... URI
      finalConn = newConn;

      // Check for password and prompt if missing (like before)
      size_t start = std::string("postgres://").size();
      size_t at_pos = finalConn.find('@', start);

      if (at_pos != std::string::npos) {
        std::string userinfo = finalConn.substr(start, at_pos - start);

        if (userinfo.find(':') == std::string::npos) {
          std::string username = userinfo;
          std::string password;

          std::cout << "No password found in URI. Enter password for user '"
                    << username << "': ";
          std::getline(std::cin, password);

          finalConn.replace(start, at_pos - start, username + ":" + password);
        }
      }
    }

    config_->dbConnection = finalConn;

    ConfigManager configManager("config.json");
    if (!configManager.load()) {
      std::cerr << "[ERROR] Failed to load config.json.\n";
      return;
    }

    configManager.getConfig().dbConnection = finalConn;

    if (configManager.save()) {
      std::cout << "[INFO] DB connection updated successfully.\n";
    } else {
      std::cerr << "[ERROR] Failed to save config.\n";
    }

    std::this_thread::sleep_for(2s);
    return;
  }

  if (key == "r") {
    const std::string defaultConn =
        "postgres://user:pass@localhost:5432/passwords";
    config_->dbConnection = defaultConn;

    ConfigManager configManager("config.json");
    if (!configManager.load()) {
      std::cerr << "[ERROR] Failed to load config.json.\n";
      return;
    }

    configManager.getConfig().dbConnection = defaultConn;

    if (configManager.save()) {
      std::cout << "[INFO] DB connection reset to default.\n";
    } else {
      std::cerr << "[ERROR] Failed to save config.\n";
    }

    std::this_thread::sleep_for(2s);
    return;
  }

  std::cout << "[INFO] Invalid input. Please try again.\n";
  std::this_thread::sleep_for(2s);
}
