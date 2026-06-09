#include "terminal.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#include "crypto/aes.h"  // random_bytes

namespace pwmgr::cli {

void clear_screen() { std::cout << "\033[2J\033[1;1H"; }

std::string prompt_line(const std::string& prompt) {
  std::cout << prompt << std::flush;
  std::string line;
  std::getline(std::cin, line);
  return line;
}

void pause() {
  std::cout << "\nPress ENTER to continue..." << std::flush;
  std::string ignore;
  std::getline(std::cin, ignore);
}

void status_ok(const std::string& msg) { std::cout << "[ OK ] " << msg << "\n"; }
void status_warn(const std::string& msg) {
  std::cout << "[WARN] " << msg << "\n";
}
void status_err(const std::string& msg) {
  std::cout << "[ERR ] " << msg << "\n";
}

namespace {
bool have(const char* cmd) {
  std::string c = "command -v ";
  c += cmd;
  c += " >/dev/null 2>&1";
  return std::system(c.c_str()) == 0;
}
}  // namespace

std::string copy_to_clipboard(const std::string& secret, int secs) {
  const char* writer = nullptr;
  std::string wiper;
  if (have("wl-copy")) {
    writer = "wl-copy";
    wiper = "sleep " + std::to_string(secs) + "; wl-copy --clear";
  } else if (have("xclip")) {
    writer = "xclip -selection clipboard";
    wiper = "sleep " + std::to_string(secs) +
            "; printf '' | xclip -selection clipboard";
  } else if (have("xsel")) {
    writer = "xsel --clipboard --input";
    wiper = "sleep " + std::to_string(secs) +
            "; printf '' | xsel --clipboard --input";
  } else {
    return "";
  }

  FILE* p = popen(writer, "w");
  if (!p) return "";
  std::fwrite(secret.data(), 1, secret.size(), p);
  pclose(p);

  std::string bg = "nohup sh -c '" + wiper + "' >/dev/null 2>&1 &";
  std::system(bg.c_str());
  return writer;
}

std::string redact_conn(const std::string& conn) {
  std::string out = conn;

  // key=value form: password=VALUE (terminated by space/tab or & in query form).
  std::size_t pos = out.find("password=");
  if (pos != std::string::npos) {
    std::size_t start = pos + std::string("password=").size();
    std::size_t end = out.find_first_of(" \t&", start);
    if (end == std::string::npos) end = out.size();
    out.replace(start, end - start, "****");
  }

  // URI form: scheme://user:PASS@host -> mask the userinfo password span.
  std::size_t scheme = out.find("://");
  if (scheme != std::string::npos) {
    std::size_t auth = scheme + 3;
    std::size_t at = out.find('@', auth);
    if (at != std::string::npos) {
      std::size_t colon = out.find(':', auth);
      if (colon != std::string::npos && colon < at)
        out.replace(colon + 1, at - (colon + 1), "****");
    }
  }
  return out;
}

std::string generate_password(std::size_t length) {
  static const std::string cs =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
      "!@#$%^&*()-_=+[]{}";
  const std::size_t n = cs.size();
  const unsigned limit = (256u / static_cast<unsigned>(n)) * static_cast<unsigned>(n);
  std::string out;
  out.reserve(length);
  while (out.size() < length) {
    auto rb = crypto::random_bytes(length);
    for (unsigned char b : rb) {
      if (b < limit) {  // rejection sampling avoids modulo bias
        out += cs[b % n];
        if (out.size() == length) break;
      }
    }
  }
  return out;
}

}  // namespace pwmgr::cli
