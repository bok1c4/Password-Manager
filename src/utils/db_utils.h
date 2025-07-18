#ifndef DB_UTILS_H
#define DB_UTILS_H

#include <string>
#include <vector>

bool save_to_db(const std::string &dbConn, const std::string &password,
                const std::string &note);

std::vector<std::pair<int, std::string>>
get_all_password_notes(const std::string &dbConn);

std::pair<std::string, std::string>
get_password_by_note_id(const std::string &dbConn, int id);

#endif // DB_UTILS_H
