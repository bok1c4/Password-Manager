#include "screens.h"

#include <cstdint>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/crypto.h>

#include "commands.h"
#include "config/config.h"
#include "crypto/encryptor.h"
#include "crypto/gpg.h"
#include "db/repository.h"
#include "sharing/rewrap.h"
#include "terminal.h"

namespace pwmgr::cli {

// ---------------- Main menu ----------------
void MainMenuScreen::render() {
  std::cout << "\n";
  std::cout << "+============================================+\n";
  std::cout << "|         PASSWORD MANAGER  (rewrite)        |\n";
  std::cout << "+--------------------------------------------+\n";
  std::cout << "|  [1] Generate & store a new password       |\n";
  std::cout << "|  [2] View / search stored passwords        |\n";
  std::cout << "|  [3] Manage database connection            |\n";
  std::cout << "|  [4] Encryption / keys (info)              |\n";
  std::cout << "|  [5] Devices (multi-device sharing)        |\n";
  std::cout << "|  [q] Quit                                  |\n";
  std::cout << "+============================================+\n";
  std::cout << "> " << std::flush;
}

void MainMenuScreen::handle_input(const std::string& line) {
  if (line == "1")
    m_->push(std::make_unique<GenerateScreen>(m_, c_));
  else if (line == "2")
    m_->push(std::make_unique<ListScreen>(m_, c_));
  else if (line == "3")
    m_->push(std::make_unique<ManageDbScreen>(m_, c_));
  else if (line == "4")
    m_->push(std::make_unique<EncryptionScreen>(m_, c_));
  else if (line == "5")
    m_->push(std::make_unique<DevicesScreen>(m_, c_));
  else if (line == "q" || line == "Q")
    m_->pop();
  // anything else: just re-render
}

// ---------------- Generate ----------------
std::string GenerateScreen::generate_password_() { return generate_password(20); }

void GenerateScreen::render() {
  std::cout << "\n+============================================+\n";
  std::cout << "|            GENERATE NEW PASSWORD           |\n";
  std::cout << "+--------------------------------------------+\n";
  std::cout << "  Candidate: " << password_ << "\n";
  std::cout << "+--------------------------------------------+\n";
  std::cout << "  [s] save with a note   [r] regenerate   [b] back\n";
  std::cout << "> " << std::flush;
}

void GenerateScreen::handle_input(const std::string& line) {
  if (line == "r" || line == "R") {
    password_ = generate_password(20);
  } else if (line == "s" || line == "S") {
    std::string note = prompt_line("Note / label for this password: ");
    if (note.empty()) {
      status_warn("A note is required (it's how you'll find the entry).");
      pause();
      return;
    }
    try {
      std::size_t n_devices = c_->keys->active_devices().size();
      std::int64_t id = sharing::store_new_entry(
          *c_->keys, c_->config->recipient_fingerprint(), password_, note);
      status_ok("Saved entry #" + std::to_string(id) +
                " (AES-256-GCM, v2; key GPG-wrapped to " +
                std::to_string(n_devices) + " device(s) + legacy).");
    } catch (const std::exception& ex) {
      status_err(std::string("Save failed: ") + ex.what());
    }
    pause();
    m_->pop();
  } else if (line == "b" || line == "B") {
    m_->pop();
  }
}

// ---------------- List / search ----------------
void ListScreen::render() {
  std::cout << "\n+============================================+\n";
  std::cout << "|             STORED PASSWORDS               |\n";
  if (filter_) std::cout << "|  filter: " << *filter_ << "\n";
  std::cout << "+--------------------------------------------+\n";
  try {
    auto rows = filter_ ? c_->repo->search_notes(*filter_)
                        : c_->repo->list_notes();
    if (rows.empty()) {
      std::cout << "  (no entries)\n";
    } else {
      // Annotate each entry with the devices that can decrypt it (the access
      // matrix). Pre-migration there are no device tables, so skip it.
      const bool migrated = c_->repo->has_device_tables();
      std::vector<db::Device> devices;
      std::map<std::int64_t, const db::Device*> idx;
      std::map<std::int64_t, std::vector<std::int64_t>> by_entry;
      if (migrated) {
        devices = c_->repo->list_devices();
        for (const auto& d : devices) idx.emplace(d.id, &d);
        by_entry = db::wraps_by_entry(c_->repo->wrap_pairs());
      }
      if (migrated)
        std::cout << "  (-> = devices that can decrypt)\n";
      for (const auto& r : rows) {
        std::cout << "  #" << r.id << "  [v" << r.enc_version << "]  " << r.note;
        if (migrated) {
          std::string who;
          if (auto it = by_entry.find(r.id); it != by_entry.end())
            for (std::int64_t dev_id : it->second)
              if (auto d = idx.find(dev_id); d != idx.end())
                who += (who.empty() ? "" : ", ") + d->second->name;
          std::cout << "\n        -> " << (who.empty() ? "(no devices)" : who);
        }
        std::cout << "\n";
      }
    }
  } catch (const std::exception& ex) {
    status_err(std::string("Could not read entries: ") + ex.what());
  }
  std::cout << "+--------------------------------------------+\n";
  std::cout << "  [<id>] open   [/] search   [c] clear filter   [b] back\n";
  std::cout << "> " << std::flush;
}

void ListScreen::handle_input(const std::string& line) {
  if (line == "b" || line == "B") {
    m_->pop();
    return;
  }
  if (line == "/") {
    filter_ = prompt_line("Search notes: ");
    return;
  }
  if (line == "c" || line == "C") {
    filter_.reset();
    return;
  }
  try {
    std::int64_t id = std::stoll(line);
    m_->push(std::make_unique<EntryScreen>(m_, c_, id));
  } catch (const std::exception&) {
    status_warn("Enter a numeric id, '/', 'c', or 'b'.");
    pause();
  }
}

// ---------------- Single entry ----------------
void EntryScreen::render() {
  std::cout << "\n+============================================+\n";
  std::cout << "|              PASSWORD ENTRY                |\n";
  std::cout << "+--------------------------------------------+\n";
  try {
    auto e = c_->repo->get_entry(id_);
    if (!e) {
      std::cout << "  Entry #" << id_ << " not found.\n";
      std::cout << "  [b] back\n> " << std::flush;
      return;
    }
    std::cout << "  ID:   #" << e->id << "\n";
    std::cout << "  Note: " << e->note << "\n";
    std::cout << "  Enc:  v" << e->enc_version
              << (e->enc_version == 1 ? " (legacy CBC)" : " (AES-256-GCM)")
              << "\n";
  } catch (const std::exception& ex) {
    status_err(std::string("Read failed: ") + ex.what());
  }
  std::cout << "+--------------------------------------------+\n";
  std::cout << "  [c] copy to clipboard   [s] show (transient)\n";
  std::cout << "  [e] edit password   [n] rename note   [d] delete   [b] back\n";
  std::cout << "> " << std::flush;
}

void EntryScreen::handle_input(const std::string& line) {
  if (line == "b" || line == "B") {
    m_->pop();
    return;
  }
  std::optional<db::Entry> e;
  try {
    e = c_->repo->get_entry(id_);
  } catch (const std::exception& ex) {
    status_err(std::string("Read failed: ") + ex.what());
    pause();
    return;
  }
  if (!e) {
    status_warn("Entry no longer exists.");
    pause();
    m_->pop();
    return;
  }

  if (line == "c" || line == "C") {
    try {
      // Per-device wrap when enrolled; unconditional legacy aes_key fallback
      // keeps pre-migration DBs and the original v1 rows decrypting.
      std::string wrap =
          c_->repo->wrapped_key_for(e->id, c_->config->recipient_fingerprint())
              .value_or(e->aes_key_armored);
      std::string secret = c_->enc->decrypt(e->password_blob, wrap);
      std::string tool = copy_to_clipboard(secret, 20);
      OPENSSL_cleanse(secret.data(), secret.size());  // wipe local plaintext
      if (tool.empty())
        status_warn("No clipboard tool found (install wl-copy, xclip, or xsel).");
      else
        status_ok("Copied via " + tool + " (clipboard clears in 20s).");
    } catch (const std::exception& ex) {
      status_err(std::string("Decrypt failed: ") + ex.what());
    }
    pause();
  } else if (line == "s" || line == "S") {
    try {
      // Per-device wrap when enrolled; unconditional legacy aes_key fallback
      // keeps pre-migration DBs and the original v1 rows decrypting.
      std::string wrap =
          c_->repo->wrapped_key_for(e->id, c_->config->recipient_fingerprint())
              .value_or(e->aes_key_armored);
      std::string secret = c_->enc->decrypt(e->password_blob, wrap);
      // Alternate screen buffer: keeps the plaintext out of normal scrollback.
      std::cout << "\033[?1049h\033[2J\033[H";
      std::cout << "Password for entry #" << id_ << ":\n\n  ";
      if (secret.empty())
        std::cout << "(decrypted to empty — check key/passphrase)";
      else
        std::cout << secret;
      std::cout << "\n";
      prompt_line("\nPress ENTER to clear and return...");
      std::cout << "\033[?1049l" << std::flush;
      OPENSSL_cleanse(secret.data(), secret.size());  // wipe local plaintext
    } catch (const std::exception& ex) {
      status_err(std::string("Decrypt failed: ") + ex.what());
      pause();
    }
  } else if (line == "e" || line == "E") {
    std::string np = prompt_line("New password (blank = generate strong): ");
    if (np.empty()) np = generate_password(20);
    try {
      sharing::replace_entry_password(
          *c_->keys, c_->config->recipient_fingerprint(), id_, np);
      status_ok("Password updated and re-encrypted (v2, all devices).");
    } catch (const std::exception& ex) {
      status_err(std::string("Update failed: ") + ex.what());
    }
    pause();
  } else if (line == "n" || line == "N") {
    std::string nn = prompt_line("New note: ");
    if (nn.empty()) {
      status_warn("Note unchanged (blank not allowed).");
    } else {
      try {
        c_->repo->update_note(id_, nn);
        status_ok("Note updated.");
      } catch (const std::exception& ex) {
        status_err(std::string("Update failed: ") + ex.what());
      }
    }
    pause();
  } else if (line == "d" || line == "D") {
    std::string confirm = prompt_line("Type DELETE to permanently remove: ");
    if (confirm == "DELETE") {
      try {
        c_->repo->delete_entry(id_);
        status_ok("Entry deleted.");
        pause();
        m_->pop();
        return;
      } catch (const std::exception& ex) {
        status_err(std::string("Delete failed: ") + ex.what());
        pause();
      }
    } else {
      status_warn("Delete cancelled.");
      pause();
    }
  }
}

// ---------------- Devices ----------------
void DevicesScreen::render() {
  std::cout << "\n+============================================+\n";
  std::cout << "|        DEVICES (multi-device sharing)      |\n";
  std::cout << "+--------------------------------------------+\n";
  try {
    if (!c_->repo->has_device_tables()) {
      std::cout << "  Device tables not migrated yet.\n";
      std::cout << "  Run 'pwmgr migrate' (after a backup) to enable\n";
      std::cout << "  multi-device sharing. Nothing runs automatically.\n";
    } else {
      auto devices = c_->repo->list_devices();
      if (devices.empty()) {
        std::cout << "  (no devices registered)\n";
      } else {
        // Per-device decryptable coverage = rows of password_keys for it.
        const std::int64_t total =
            static_cast<std::int64_t>(c_->repo->all_entry_ids().size());
        const auto counts = db::count_by_device(c_->repo->wrap_pairs());
        bool gap = false;
        for (const auto& d : devices) {
          std::int64_t c = 0;
          if (auto it = counts.find(d.id); it != counts.end()) c = it->second;
          if (d.status == "active" && c < total) gap = true;
          std::cout << "  #" << d.id << "  " << d.name << "  [" << d.status
                    << "]  decrypts " << c << "/" << total << "\n      "
                    << d.fingerprint << "\n";
        }
        if (total > 0) {
          std::cout << "+--------------------------------------------+\n";
          if (gap)
            std::cout << "  [WARN] an active device is missing wraps — press "
                         "[w] to rewrap\n";
          else
            std::cout << "  [OK] every active device can decrypt all " << total
                      << " entries\n";
        }
      }
    }
  } catch (const std::exception& ex) {
    status_err(std::string("Could not read devices: ") + ex.what());
  }
  std::cout << "+--------------------------------------------+\n";
  std::cout << "  [a] add   [r] revoke   [w] rewrap (resume)   [b] back\n";
  std::cout << "> " << std::flush;
}

void DevicesScreen::handle_input(const std::string& line) {
  if (line == "b" || line == "B") {
    m_->pop();
    return;
  }
  if (line == "a" || line == "A") {
    std::string name = prompt_line("Device name (e.g. arch-laptop): ");
    std::string path = prompt_line("Path to its exported public key (.asc): ");
    if (name.empty() || path.empty()) {
      status_warn("Cancelled (empty input).");
    } else {
      // Fingerprint is prompted inside cmd_device_add (TTY path).
      cmd_device_add(*c_, name, path, "");
    }
    pause();
  } else if (line == "r" || line == "R") {
    std::string name = prompt_line("Device name to revoke: ");
    if (name.empty()) {
      status_warn("Cancelled (empty input).");
    } else {
      cmd_device_revoke(*c_, name, RevokeMode::Prompt);
    }
    pause();
  } else if (line == "w" || line == "W") {
    cmd_rewrap(*c_);
    pause();
  }
}

// ---------------- Manage DB ----------------
void ManageDbScreen::render() {
  std::cout << "\n+============================================+\n";
  std::cout << "|          MANAGE DATABASE CONNECTION        |\n";
  std::cout << "+--------------------------------------------+\n";
  std::cout << "  Current: " << redact_conn(c_->config->db_connection) << "\n";
  std::cout << "+--------------------------------------------+\n";
  std::cout << "  [t] test   [a] change connection   [b] back\n";
  std::cout << "> " << std::flush;
}

void ManageDbScreen::handle_input(const std::string& line) {
  if (line == "b" || line == "B") {
    m_->pop();
    return;
  }
  if (line == "t" || line == "T") {
    try {
      if (c_->repo->test_connection())
        status_ok("Connection is open.");
      else
        status_warn("Connection is not open.");
    } catch (const std::exception& ex) {
      status_err(std::string("Test failed: ") + ex.what());
    }
    pause();
    return;
  }
  if (line == "a" || line == "A") {
    std::string nc =
        prompt_line("New connection (postgres URI or libpq key=val): ");
    if (nc.empty()) {
      status_warn("Cancelled (empty input).");
      pause();
      return;
    }
    std::cout << "  CURRENT: " << redact_conn(c_->config->db_connection) << "\n";
    std::cout << "  NEW:     " << redact_conn(nc) << "\n";
    std::string confirm = prompt_line("Type 'yes' to save this change: ");
    if (confirm == "yes") {
      std::string prev = c_->config->db_connection;
      c_->config->db_connection = nc;
      try {
        c_->cfgmgr->save(*c_->config);
        status_ok("Saved. Restart the app to use the new connection.");
      } catch (const std::exception& ex) {
        c_->config->db_connection = prev;  // roll back in-memory
        status_err(std::string("Save refused: ") + ex.what());
      }
    } else {
      status_warn("Change cancelled.");
    }
    pause();
  }
}

// ---------------- Encryption info ----------------
void EncryptionScreen::render() {
  const auto& cfg = *c_->config;
  std::cout << "\n+============================================+\n";
  std::cout << "|              ENCRYPTION / KEYS             |\n";
  std::cout << "+--------------------------------------------+\n";
  std::cout << "  Private key : " << cfg.private_key.username << "  ("
            << cfg.private_key.path << ")\n";
  std::cout << "  Recipients  :\n";
  for (const auto& k : cfg.public_keys)
    std::cout << "    - " << k.username << "  " << k.fingerprint << "\n";
  std::string recip = cfg.recipient_fingerprint();
  bool have_secret = crypto::gpg_has_secret_key(recip);
  std::cout << "  Decrypt key present in keyring: "
            << (have_secret ? "yes" : "NO  <-- decryption will fail") << "\n";
  std::cout << "+--------------------------------------------+\n";
  std::cout << "  Key changes are intentionally done by editing the config\n";
  std::cout << "  file directly (avoids accidentally orphaning your data).\n";
  std::cout << "  [b] back\n> " << std::flush;
}

void EncryptionScreen::handle_input(const std::string& line) {
  if (line == "b" || line == "B") m_->pop();
}

}  // namespace pwmgr::cli
