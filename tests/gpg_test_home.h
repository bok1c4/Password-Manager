// RAII ephemeral GNUPGHOME for tests: throwaway no-passphrase keys in a temp
// dir, so the crypto/sharing lifecycle is provable under plain `make test`
// with zero real secrets and no contact with the user's keyring. gpgme spawns
// gpg per operation, so the GNUPGHOME env var set here is honored per call.
// Restoring the previous value in the destructor is mandatory: a later
// --gated run in the same process must still reach the real keyring.
#pragma once
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

namespace tf {

class EphemeralKeyring {
 public:
  EphemeralKeyring() {
    char tmpl[] = "/tmp/pwmgr_gpg_test_XXXXXX";
    char* dir = ::mkdtemp(tmpl);
    if (dir == nullptr) throw std::runtime_error("mkdtemp failed");
    dir_ = dir;
    ::chmod(dir_.c_str(), 0700);
    if (const char* old = std::getenv("GNUPGHOME")) {
      had_old_ = true;
      old_ = old;
    }
    ::setenv("GNUPGHOME", dir_.c_str(), 1);
  }

  EphemeralKeyring(const EphemeralKeyring&) = delete;
  EphemeralKeyring& operator=(const EphemeralKeyring&) = delete;

  ~EphemeralKeyring() {
    // Kill this keyring's agent before the dir disappears (env still points
    // at it here, so gpgconf targets the right home).
    std::system("gpgconf --kill all >/dev/null 2>&1");
    if (had_old_)
      ::setenv("GNUPGHOME", old_.c_str(), 1);
    else
      ::unsetenv("GNUPGHOME");
    std::error_code ec;
    std::filesystem::remove_all(dir_, ec);  // best-effort cleanup
  }

  const std::string& dir() const { return dir_; }

  // Generates a no-protection ed25519/cv25519 key and returns its 40-char
  // fingerprint. Throws on failure.
  std::string gen_key(const std::string& name) {
    const std::string batch_path = dir_ + "/batch_" + name;
    {
      std::ofstream b(batch_path);
      b << "%no-protection\n"
        << "Key-Type: eddsa\n"
        << "Key-Curve: ed25519\n"
        << "Subkey-Type: ecdh\n"
        << "Subkey-Curve: cv25519\n"
        << "Name-Real: " << name << "\n"
        << "Expire-Date: 0\n"
        << "%commit\n";
    }
    if (std::system(("gpg --batch --generate-key " + batch_path +
                     " >/dev/null 2>&1")
                        .c_str()) != 0) {
      throw std::runtime_error("gpg --batch --generate-key failed");
    }
    return fingerprint_of(name);
  }

  // Primary fingerprint of the key whose uid contains `name`.
  std::string fingerprint_of(const std::string& name) const {
    FILE* p = ::popen("gpg --list-keys --with-colons 2>/dev/null", "r");
    if (p == nullptr) throw std::runtime_error("popen gpg --list-keys failed");
    std::string out;
    char buf[4096];
    std::size_t n;
    while ((n = ::fread(buf, 1, sizeof(buf), p)) > 0) out.append(buf, n);
    ::pclose(p);
    // Colon format: a pub record, then its fpr record, then uid record(s).
    std::string candidate, match;
    std::size_t pos = 0;
    while (pos < out.size()) {
      std::size_t eol = out.find('\n', pos);
      if (eol == std::string::npos) eol = out.size();
      std::string line = out.substr(pos, eol - pos);
      pos = eol + 1;
      if (line.rfind("fpr:", 0) == 0) {
        // field 10 holds the fingerprint: fpr:::::::::FPR:
        std::size_t colons = 0, start = 0;
        for (std::size_t i = 0; i < line.size(); ++i) {
          if (line[i] == ':' && ++colons == 9) start = i + 1;
          if (colons == 10) {
            candidate = line.substr(start, i - start);
            break;
          }
        }
      } else if (line.rfind("uid:", 0) == 0 &&
                 line.find(name) != std::string::npos) {
        match = candidate;
      }
    }
    if (match.empty())
      throw std::runtime_error("no key with uid containing '" + name + "'");
    return match;
  }

 private:
  std::string dir_;
  std::string old_;
  bool had_old_ = false;
};

}  // namespace tf
