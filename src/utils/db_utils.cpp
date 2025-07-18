#include <fstream>
#include <iostream>
#include <pqxx/pqxx>
#include <vector>

bool save_to_db(const std::string &dbConn, const std::string &password,
                const std::string &note) {
  try {
    pqxx::connection conn(dbConn);
    if (!conn.is_open()) {
      std::cerr << "[ERROR] Failed to connect to database.\n";
      return false;
    }

    pqxx::work txn(conn);
    txn.exec_params("INSERT INTO passwords (password, note) VALUES ($1, $2)",
                    password, note);
    txn.commit();

    std::cout << "[INFO] Password saved to database.\n";
    return true;
  } catch (const std::exception &e) {
    std::cerr << "[ERROR] DB exception: " << e.what() << "\n";
    std::ofstream log_file("db_errors.log", std::ios::app);
    if (log_file.is_open()) {
      log_file << "[ERROR] Failed to save to DB: " << e.what() << "\n";
    }
    return false;
  }
}

std::vector<std::pair<int, std::string>>
get_all_password_notes(const std::string &dbConn) {
  std::vector<std::pair<int, std::string>> results;

  try {
    pqxx::connection conn(dbConn);
    pqxx::work txn(conn);

    pqxx::result r =
        txn.exec("SELECT id, passwords.note FROM passwords ORDER BY id ASC");

    for (const auto &row : r) {
      int id = row[0].as<int>();
      std::string note = row[1].as<std::string>();
      results.emplace_back(id, note);
    }

    txn.commit();
  } catch (const std::exception &e) {
    std::cerr << "[ERROR] DB read error: " << e.what() << "\n";
  }

  return results;
}

std::pair<std::string, std::string>
get_password_by_note_id(const std::string &dbConn, int id) {
  try {
    pqxx::connection conn(dbConn);
    pqxx::work txn(conn);

    pqxx::result r = txn.exec_params(
        "SELECT password, passwords.note FROM passwords WHERE id = $1", id);

    if (r.size() == 1) {
      std::string password = r[0][0].as<std::string>();
      std::string note = r[0][1].as<std::string>();
      return {password, note};
    }
  } catch (const std::exception &e) {
    std::cerr << "[ERROR] Failed to retrieve entry: " << e.what() << "\n";
  }

  return {"", ""};
}
