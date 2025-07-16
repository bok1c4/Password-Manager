#ifndef DB_UTILS_H
#define DB_UTILS_H

#include <string>
#include <vector>

bool save_to_db(const std::string &password, const std::string &note);

std::vector<std::pair<int, std::string>> get_all_password_notes();

std::pair<std::string, std::string> get_password_by_note_id(int id);

#endif // DB_UTILS_H
