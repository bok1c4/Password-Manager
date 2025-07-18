#include <fstream>
#include <iostream>
#include <postgresql/libpq-fe.h>
#include <pqxx/pqxx>
#include <vector>

bool test_db_conn(const std::string &dbConn) {
  PGconn *conn = PQconnectdb(dbConn.c_str());

  if (PQstatus(conn) != CONNECTION_OK) {
    std::cerr << "[ERROR] Connection failed: " << PQerrorMessage(conn)
              << std::endl;
    PQfinish(conn);
    return false;
  }

  std::cout << "[INFO] Database connection successful." << std::endl;
  PQfinish(conn);
  return true;
}

bool save_to_db(const std::string &dbConn, const std::string &encryptedPassword,
                const std::string &encryptedAesKey, const std::string &note) {
  try {
    pqxx::connection conn(dbConn);
    if (!conn.is_open()) {
      std::cerr << "[ERROR] Failed to connect to database.\n";
      return false;
    }

    pqxx::work txn(conn);
    txn.exec_params("INSERT INTO passwords (password, aes_key, note) "
                    "VALUES ($1, $2, $3)",
                    encryptedPassword, encryptedAesKey, note);
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

bool save_public_key_ref(const std::string &dbConn,
                         const std::string &pubKeyContent,
                         const std::string &fingerprint,
                         const std::string &username) {
  try {
    pqxx::connection conn(dbConn);
    if (!conn.is_open()) {
      std::cerr << "[ERROR] Could not open DB connection.\n";
      return false;
    }

    pqxx::work txn(conn);
    txn.exec_params("INSERT INTO user_public_keys (public_key, fingerprint, "
                    "username) VALUES ($1, $2, $3)",
                    pubKeyContent, fingerprint, username);
    txn.commit();

    std::cout << "[INFO] Public key saved to database.\n";
    return true;
  } catch (const std::exception &e) {
    std::cerr << "[ERROR] DB insert failed: " << e.what() << "\n";
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

std::optional<std::string>
find_user_by_key_or_username(const std::string &dbConn,
                             const std::string &pubKeyContent,
                             const std::string &username) {
  try {
    pqxx::connection conn(dbConn);
    pqxx::work txn(conn);

    pqxx::result r =
        txn.exec_params("SELECT username FROM user_public_keys WHERE "
                        "public_key = $1 OR username = $2 LIMIT 1",
                        pubKeyContent, username);

    txn.commit();

    if (r.size() == 1) {
      // Return found username
      return r[0][0].as<std::string>();
    }
  } catch (const std::exception &e) {
    std::cerr << "[ERROR] DB search failed: " << e.what() << "\n";
  }
  return std::nullopt;
}
