#ifndef DB_UTILS_H
#define DB_UTILS_H

#include <optional>
#include <string>
#include <vector>

bool test_db_conn(const std::string &dbConn);

bool save_to_db(const std::string &dbConn, const std::string &encryptedPassword,
                const std::string &encryptedAesKey, const std::string &note);

bool save_public_key_ref(const std::string &dbConn,
                         const std::string &pubKeyContent,
                         const std::string &username);

std::vector<std::pair<int, std::string>>
get_all_password_notes(const std::string &dbConn);

std::pair<std::string, std::string>
get_password_by_note_id(const std::string &dbConn, int id);

std::optional<std::string>
find_user_by_key_or_username(const std::string &dbConn,
                             const std::string &pubKeyContent,
                             const std::string &username);

#endif // DB_UTILS_H
