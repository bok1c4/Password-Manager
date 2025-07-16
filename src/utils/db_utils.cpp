#include <fstream>
#include <iostream>
#include <pqxx/pqxx>

bool save_to_db(const std::string &password, const std::string &note) {
  try {
    pqxx::connection conn("host=192.168.100.138 port=5432 dbname=mydb "
                          "user=dbuser password=temp123");

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
