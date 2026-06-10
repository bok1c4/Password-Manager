#include "db/device.h"

#include <cctype>

namespace pwmgr::db {

bool is_valid_fingerprint(std::string_view fpr) {
  if (fpr.size() != 40) return false;
  for (unsigned char ch : fpr) {
    if (!std::isxdigit(ch)) return false;
  }
  return true;
}

std::string normalize_fingerprint(std::string_view fpr) {
  std::string out;
  out.reserve(40);
  for (unsigned char ch : fpr) {
    if (ch == ' ') continue;
    out.push_back(static_cast<char>(std::toupper(ch)));
  }
  if (!is_valid_fingerprint(out)) return {};
  return out;
}

}  // namespace pwmgr::db
