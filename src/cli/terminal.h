#pragma once
#include <string>

namespace pwmgr::cli {

void clear_screen();
std::string prompt_line(const std::string& prompt);  // print prompt, read a line
void pause();                                         // "Press ENTER to continue"

void status_ok(const std::string& msg);
void status_warn(const std::string& msg);
void status_err(const std::string& msg);

// Copies `secret` to the clipboard via a detected tool (wl-copy/xclip/xsel),
// passing it on stdin (never argv), and schedules an auto-clear after
// `clear_after_seconds`. Returns the tool used, or "" if no tool is available.
std::string copy_to_clipboard(const std::string& secret, int clear_after_seconds);

// Returns a copy of a libpq connection string with the password value masked.
std::string redact_conn(const std::string& conn);

// CSPRNG password over a strong character set.
std::string generate_password(std::size_t length);

}  // namespace pwmgr::cli
