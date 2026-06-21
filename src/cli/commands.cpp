#include "commands.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <unistd.h>

#include <openssl/crypto.h>

#include "config/config.h"
#include "crypto/encryptor.h"
#include "crypto/gpg.h"
#include "db/repository.h"
#include "screen.h"
#include "sharing/rewrap.h"
#include "terminal.h"

namespace pwmgr::cli {

namespace {

bool stdin_is_tty() { return ::isatty(STDIN_FILENO) == 1; }

void progress_line(std::size_t done, std::size_t total, const std::string& what) {
  std::fprintf(stderr, "  [%zu/%zu] %s\n", done, total, what.c_str());
}

// device_id -> Device*, to turn the wrap matrix's ids into device names.
// Borrows from `devices`, which must outlive the returned map.
std::map<std::int64_t, const db::Device*> index_devices(
    const std::vector<db::Device>& devices) {
  std::map<std::int64_t, const db::Device*> m;
  for (const auto& d : devices) m.emplace(d.id, &d);
  return m;
}

// Resolve one ACTIVE device by name. nullopt (no print) if not found.
std::optional<db::Device> resolve_active_device(AppContext& ctx,
                                                const std::string& name) {
  for (const auto& d : ctx.repo->active_devices())
    if (d.name == name) return d;
  return std::nullopt;
}

// Resolve a comma-separated list of ACTIVE device names to Device objects
// (de-duplicated). Returns false and prints the first unknown name.
bool resolve_active_devices(AppContext& ctx, const std::string& csv,
                            std::vector<db::Device>& out) {
  const auto active = ctx.repo->active_devices();
  std::stringstream ss(csv);
  std::string tok;
  while (std::getline(ss, tok, ',')) {
    const auto b = tok.find_first_not_of(" \t");
    if (b == std::string::npos) continue;  // skip blank tokens
    const auto e = tok.find_last_not_of(" \t");
    const std::string name = tok.substr(b, e - b + 1);
    auto it = std::find_if(active.begin(), active.end(),
                           [&](const db::Device& d) { return d.name == name; });
    if (it == active.end()) {
      std::cerr << "[ERROR] no active device named '" << name
                << "' (see 'pwmgr device list')\n";
      return false;
    }
    if (std::none_of(out.begin(), out.end(), [&](const db::Device& d) {
          return d.id == it->id;
        }))
      out.push_back(*it);
  }
  if (out.empty()) {
    std::cerr << "[ERROR] --devices listed no known device\n";
    return false;
  }
  return true;
}

void print_backup_warning() {
  std::cerr << "[WARN] This rewrites every passwords row (new key + v2 GCM). "
               "Take a fresh backup first: ./scripts/backup.sh\n";
}

void print_incomplete_warning(const std::string& name) {
  std::cerr << "[WARN] Revocation INCOMPLETE: '" << name
            << "' may hold cached keys. Run 'pwmgr rotate' to finish.\n";
}

// The parts of revocation that live outside the database (docs/DEPLOYMENT.md).
void print_revoke_checklist(const std::string& name) {
  std::cerr
      << "[INFO] Finish revoking '" << name << "' outside the DB too:\n"
      << "       - delete its onion auth file: /var/lib/tor/pwmgr/"
         "authorized_clients/" << name << ".auth, then: systemctl reload tor\n"
      << "       - rotate the shared Postgres password "
         "(scripts/rotate-db-password.sh --apply) — every enrolled device "
         "knows it\n"
      << "       (docs/DEPLOYMENT.md)\n";
}

}  // namespace

db::FoundingDevice make_founding_device(const config::AppConfig& cfg) {
  db::FoundingDevice f;
  f.name = cfg.effective_device_name();
  f.fingerprint = cfg.recipient_fingerprint();
  for (const auto& k : cfg.public_keys) {
    if (k.fingerprint == f.fingerprint && !k.path.empty()) {
      std::ifstream in(k.path, std::ios::binary);
      if (in) {
        std::stringstream ss;
        ss << in.rdbuf();
        f.public_key_armored = ss.str();
      } else {
        std::cerr << "[WARN] could not read public key file " << k.path
                  << " (devices.public_key left empty; completed at device "
                     "add time)\n";
      }
      break;
    }
  }
  return f;
}

void print_usage(std::ostream& out) {
  out << "Usage: pwmgr [command]\n"
         "\n"
         "  (no command)                       interactive menu\n"
         "  migrate                            apply schema migrations incl. "
         "v2 (devices/password_keys)\n"
         "  status                             devices, entries, per-device "
         "decryptable coverage + readiness\n"
         "  entry add --note <s> [--devices a,b,c]\n"
         "                                     store a new entry from STDIN "
         "(default: all active devices); prints id\n"
         "  entry list [--porcelain]           every entry + which devices can "
         "decrypt it\n"
         "  entry show <id>                    print the decrypted password "
         "to stdout\n"
         "  entry grant <id> <device>          give a device access to one "
         "entry\n"
         "  entry revoke <id> <device>         remove a device from one entry "
         "(rotates that entry)\n"
         "  device list [--porcelain]          registered devices "
         "(porcelain: name<TAB>fpr<TAB>status)\n"
         "  device add <name> <pubkey.asc> --fpr <40hex>\n"
         "                                     enroll a device (verify the "
         "fingerprint out-of-band!)\n"
         "  device revoke <name> [--rotate|--no-rotate]\n"
         "                                     revoke; rotation strongly "
         "recommended (default: prompt)\n"
         "  rewrap                             resume/repair the wrap matrix "
         "for all active devices\n"
         "  rotate [--yes]                     new key per entry, re-encrypt "
         "v2 GCM, re-wrap to all devices\n"
         "  help                               this text\n"
         "\n"
         "Exit codes: 0 ok, 1 operation failed, 2 usage/consent, 3 "
         "fingerprint mismatch.\n";
}

int cmd_migrate(AppContext& ctx) {
  try {
    ctx.repo->apply_migrations();
    ctx.repo->apply_migrations_v2(make_founding_device(*ctx.config));
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] migrate failed: " << e.what() << "\n";
    return 1;
  }
  try {
    const auto devices = ctx.repo->list_devices();
    const auto entries = ctx.repo->all_entry_ids();
    std::cout << "Migration complete (schema v2).\n"
              << "Devices registered: " << devices.size() << "\n";
    if (auto f = ctx.repo->founding_device()) {
      std::cout << "Founding device '" << f->name << "' ("
                << f->fingerprint << ") wraps "
                << ctx.repo->entry_ids_wrapped_for(f->id).size() << "/"
                << entries.size() << " entries\n";
    }
  } catch (const std::exception& e) {
    std::cerr << "[WARN] migrated, but could not print summary: " << e.what()
              << "\n";
  }
  return 0;
}

int cmd_entry_add(AppContext& ctx, const std::string& note,
                  const std::string& devices_csv) {
  // Resolve the recipient subset BEFORE consuming stdin, so a bad name fails
  // fast without swallowing the password.
  std::vector<db::Device> recipients;
  const bool subset = !devices_csv.empty();
  if (subset && !resolve_active_devices(ctx, devices_csv, recipients)) return 2;

  std::string password;
  if (!std::getline(std::cin, password) || password.empty()) {
    std::cerr << "[ERROR] entry add: expected the password on stdin\n";
    return 2;
  }
  try {
    const std::string& fpr = ctx.config->recipient_fingerprint();
    std::int64_t id =
        subset ? sharing::store_new_entry_for(*ctx.keys, fpr, password, note,
                                              recipients)
               : sharing::store_new_entry(*ctx.keys, fpr, password, note);
    OPENSSL_cleanse(password.data(), password.size());
    std::cout << id << "\n";  // the id is the whole stdout contract
    return 0;
  } catch (const std::exception& e) {
    OPENSSL_cleanse(password.data(), password.size());
    std::cerr << "[ERROR] save failed: " << e.what() << "\n";
    return 1;
  }
}

int cmd_entry_grant(AppContext& ctx, std::int64_t id, const std::string& device) {
  if (!ctx.repo->has_device_tables()) {
    std::cerr << "[ERROR] device tables not migrated — run 'pwmgr migrate'\n";
    return 1;
  }
  if (!ctx.repo->get_entry(id)) {
    std::cerr << "[ERROR] entry " << id << " not found\n";
    return 1;
  }
  auto dev = resolve_active_device(ctx, device);
  if (!dev) {
    std::cerr << "[ERROR] no active device named '" << device << "'\n";
    return 1;
  }
  try {
    sharing::grant_entry_to_device(*ctx.keys,
                                   ctx.config->recipient_fingerprint(), id, *dev);
    std::cerr << "[OK] entry " << id << " is now decryptable by '" << device
              << "'\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] grant failed: " << e.what() << "\n"
              << "        (you can only share an entry this device can "
                 "decrypt)\n";
    return 1;
  }
}

int cmd_entry_revoke(AppContext& ctx, std::int64_t id,
                     const std::string& device) {
  if (!ctx.repo->has_device_tables()) {
    std::cerr << "[ERROR] device tables not migrated — run 'pwmgr migrate'\n";
    return 1;
  }
  if (!ctx.repo->get_entry(id)) {
    std::cerr << "[ERROR] entry " << id << " not found\n";
    return 1;
  }
  // Build the remaining recipient set (current members minus `device`).
  const auto active = ctx.repo->active_devices();  // named: idx borrows from it
  const auto idx = index_devices(active);
  std::vector<db::Device> remaining;
  bool was_member = false;
  for (std::int64_t did : ctx.repo->device_ids_for_entry(id)) {
    auto it = idx.find(did);
    if (it == idx.end()) continue;
    if (it->second->name == device) {
      was_member = true;
      continue;
    }
    remaining.push_back(*it->second);
  }
  if (!was_member) {
    std::cerr << "[ERROR] '" << device << "' is not a current reader of entry "
              << id << "\n";
    return 1;
  }
  if (remaining.empty()) {
    std::cerr << "[ERROR] '" << device << "' is the only reader of entry " << id
              << " — removing it would orphan the entry.\n"
              << "        Grant another device first ('pwmgr entry grant " << id
              << " <device>').\n";
    return 2;
  }
  try {
    sharing::rotate_entry(*ctx.keys, ctx.config->recipient_fingerprint(), id,
                          remaining);
    std::cerr << "[OK] entry " << id << " rotated; '" << device
              << "' removed (its cached copy is now stale).\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] revoke failed: " << e.what() << "\n";
    return 1;
  }
}

int cmd_entry_show(AppContext& ctx, std::int64_t id) {
  try {
    auto e = ctx.repo->get_entry(id);
    if (!e) {
      std::cerr << "[ERROR] entry " << id << " not found\n";
      return 1;
    }
    std::string wrap =
        ctx.repo->wrapped_key_for(e->id, ctx.config->recipient_fingerprint())
            .value_or(e->aes_key_armored);
    std::string secret = ctx.enc->decrypt(e->password_blob, wrap);
    std::cout << secret << "\n";  // plaintext only; nothing else on stdout
    OPENSSL_cleanse(secret.data(), secret.size());
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] decrypt failed: " << e.what() << "\n";
    return 1;
  }
}

int cmd_entry_list(AppContext& ctx, bool porcelain) {
  try {
    const auto notes = ctx.repo->list_notes();
    const bool migrated = ctx.repo->has_device_tables();
    const auto devices =
        migrated ? ctx.repo->list_devices() : std::vector<db::Device>{};
    const auto idx = index_devices(devices);
    const auto by_entry =
        migrated ? db::wraps_by_entry(ctx.repo->wrap_pairs())
                 : std::map<std::int64_t, std::vector<std::int64_t>>{};

    // Names of the devices that can decrypt entry `id`, ascending by device id.
    auto names_for = [&](std::int64_t id) {
      std::vector<std::string> out;
      if (auto it = by_entry.find(id); it != by_entry.end())
        for (std::int64_t dev_id : it->second)
          if (auto d = idx.find(dev_id); d != idx.end())
            out.push_back(d->second->name);
      return out;
    };
    auto join = [](const std::vector<std::string>& v, const char* sep) {
      std::string s;
      for (const auto& x : v) s += (s.empty() ? "" : sep) + x;
      return s;
    };

    if (porcelain) {  // id<TAB>ver<TAB>note<TAB>dev1,dev2,...
      for (const auto& n : notes)
        std::cout << n.id << "\t" << n.enc_version << "\t" << n.note << "\t"
                  << join(names_for(n.id), ",") << "\n";
      return 0;
    }
    if (notes.empty()) {
      std::cout << "(no entries)\n";
      return 0;
    }
    std::cout << "  ID  VER  NOTE                            DECRYPTABLE BY\n";
    for (const auto& n : notes) {
      std::string who;
      if (!migrated)
        who = "(devices not migrated)";
      else if (const auto names = names_for(n.id); names.empty())
        who = "(none)";
      else
        who = join(names, ", ");
      std::printf("  %-3lld v%-3d %-31s %s\n", static_cast<long long>(n.id),
                  n.enc_version, n.note.c_str(), who.c_str());
    }
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] " << e.what() << "\n";
    return 1;
  }
}

int cmd_status(AppContext& ctx) {
  try {
    const auto notes = ctx.repo->list_notes();
    const std::int64_t total = static_cast<std::int64_t>(notes.size());
    int v2 = 0;
    for (const auto& n : notes)
      if (n.enc_version >= 2) ++v2;

    const std::string recip = ctx.config->recipient_fingerprint();
    std::cout << "Recipient: " << recip << "  ("
              << (crypto::gpg_has_secret_key(recip)
                      ? "secret key present"
                      : "NO secret key — cannot decrypt")
              << ")\n\n";

    if (!ctx.repo->has_device_tables()) {
      std::cout << "Devices:   tables not migrated — run 'pwmgr migrate'.\n"
                << "Entries:   " << total << " total (" << v2 << " v2, "
                << (total - v2) << " v1)\n";
      return 0;
    }

    const auto devices = ctx.repo->list_devices();
    const auto counts = db::count_by_device(ctx.repo->wrap_pairs());
    int active = 0, revoked = 0;
    for (const auto& d : devices) {
      if (d.status == "active")
        ++active;
      else
        ++revoked;
    }

    std::cout << "Devices (" << active << " active, " << revoked
              << " revoked):\n"
              << "  ID  NAME                  STATUS    CAN DECRYPT  "
                 "FINGERPRINT\n";
    bool gap = false;  // an active device that cannot decrypt every entry
    for (const auto& d : devices) {
      std::int64_t c = 0;
      if (auto it = counts.find(d.id); it != counts.end()) c = it->second;
      if (d.status == "active" && c < total) gap = true;
      std::printf("  %-3lld %-21s %-9s %4lld/%-6lld %s\n",
                  static_cast<long long>(d.id), d.name.c_str(),
                  d.status.c_str(), static_cast<long long>(c),
                  static_cast<long long>(total), d.fingerprint.c_str());
    }

    std::cout << "\nEntries:   " << total << " total (" << v2 << " v2-GCM, "
              << (total - v2) << " v1-CBC)\n\n";
    if (total == 0)
      std::cout << "Coverage:  no entries yet.\n";
    else if (active == 0)
      std::cout << "Coverage:  no active devices.\n";
    else if (gap)
      std::cout << "Coverage:  some active devices are missing wraps — run "
                   "'pwmgr rewrap'. [WARN]\n";
    else
      std::cout << "Coverage:  every active device can decrypt every entry. "
                   "[OK]\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] " << e.what() << "\n";
    return 1;
  }
}

int cmd_device_list(AppContext& ctx, bool porcelain) {
  if (!ctx.repo->has_device_tables()) {
    std::cerr << "[WARN] device tables absent — run 'pwmgr migrate' first\n";
    return 0;
  }
  try {
    const auto devices = ctx.repo->list_devices();
    if (porcelain) {
      for (const auto& d : devices)
        std::cout << d.name << "\t" << d.fingerprint << "\t" << d.status
                  << "\n";
      return 0;
    }
    if (devices.empty()) {
      std::cout << "(no devices registered — run 'pwmgr migrate')\n";
      return 0;
    }
    std::cout << "  ID  NAME                  STATUS    FINGERPRINT          "
                 "         ENROLLED\n";
    for (const auto& d : devices) {
      std::printf("  %-3lld %-21s %-9s %s  %s\n",
                  static_cast<long long>(d.id), d.name.c_str(),
                  d.status.c_str(), d.fingerprint.c_str(),
                  d.enrolled_at.c_str());
    }
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] " << e.what() << "\n";
    return 1;
  }
}

int cmd_device_add(AppContext& ctx, const std::string& name,
                   const std::string& pubkey_path, std::string expected_fpr) {
  if (!ctx.repo->has_device_tables()) {
    std::cerr << "[ERROR] device tables not migrated — run 'pwmgr migrate' "
                 "first\n";
    return 1;
  }
  std::ifstream in(pubkey_path, std::ios::binary);
  if (!in) {
    std::cerr << "[ERROR] cannot read public key file: " << pubkey_path
              << "\n";
    return 1;
  }
  std::stringstream ss;
  ss << in.rdbuf();
  const std::string armored = ss.str();

  if (expected_fpr.empty()) {
    if (!stdin_is_tty()) {
      std::cerr << "[ERROR] device add: --fpr <40hex> is required "
                   "non-interactively\n";
      return 2;
    }
    expected_fpr = prompt_line(
        "Expected 40-char fingerprint (verify it OUT-OF-BAND with the other "
        "device): ");
  }
  const std::string want = db::normalize_fingerprint(expected_fpr);
  if (want.empty()) {
    std::cerr << "[ERROR] malformed fingerprint (need exactly 40 hex chars)\n";
    return 2;
  }

  // Inspect WITHOUT importing: on mismatch, nothing has touched the keyring.
  std::string got;
  try {
    got = crypto::gpg_inspect_public_key(armored);
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] " << e.what() << "\n";
    return 1;
  }
  if (db::normalize_fingerprint(got) != want) {
    std::cerr << "[ERROR] fingerprint mismatch — NOT enrolling (key file may "
                 "have been swapped).\n"
              << "        expected " << want << "\n"
              << "        file is  " << got << "\n"
              << "        Nothing was imported.\n";
    return 3;
  }

  // Idempotency dispatch on the existing registry.
  db::Device target;
  bool already_enrolled = false;
  try {
    for (const auto& d : ctx.repo->list_devices()) {
      const bool name_match = (d.name == name);
      const bool fpr_match = (db::normalize_fingerprint(d.fingerprint) == want);
      if (!name_match && !fpr_match) continue;
      if (d.status == "revoked") {
        std::cerr << "[ERROR] '" << d.name << "' was revoked; choose a new "
                     "name — re-activating a revoked identity is not "
                     "supported (its old key must be considered burned)\n";
        return 1;
      }
      if (name_match != fpr_match) {
        std::cerr << "[ERROR] conflicting registration: device '" << d.name
                  << "' (" << d.fingerprint << ") collides with the request\n";
        return 1;
      }
      target = d;
      already_enrolled = true;
      break;
    }
    if (already_enrolled) {
      std::cerr << "[INFO] '" << name << "' already enrolled; resuming "
                   "re-wrap\n";
      crypto::gpg_import_public_key(armored);  // idempotent
    } else {
      crypto::gpg_import_public_key(armored);
      target = db::Device{0, name, want, armored, "active", ""};
      target.id = ctx.repo->add_device(target);
      std::cerr << "[OK] device '" << name << "' registered (id "
                << target.id << ")\n";
    }
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] enrollment failed: " << e.what() << "\n";
    return 1;
  }

  try {
    auto st = sharing::rewrap_all_to_device(
        *ctx.keys, target, ctx.config->recipient_fingerprint(), progress_line);
    std::cerr << "[OK] re-wrap: " << st.wrapped << " wrapped, " << st.skipped
              << " already present, " << st.total << " total\n";
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] re-wrap failed (safe to resume with 'pwmgr "
                 "rewrap'): " << e.what() << "\n";
    return 1;
  }

  std::cerr << "[INFO] Remote-access hand-over for '" << name
            << "' (docs/DEPLOYMENT.md, Part B):\n"
               "       - issue its onion auth key: "
               "scripts/onion-auth-keygen.sh " << name << "\n"
               "       - hand over: onion address, ca.crt (LAN), socat unit "
               "template\n";
  return 0;
}

int cmd_device_revoke(AppContext& ctx, const std::string& name,
                      RevokeMode mode) {
  if (!ctx.repo->has_device_tables()) {
    std::cerr << "[ERROR] device tables not migrated — nothing to revoke\n";
    return 1;
  }
  if (mode == RevokeMode::Prompt && !stdin_is_tty()) {
    std::cerr << "[ERROR] non-interactive revoke requires --rotate or "
                 "--no-rotate\n";
    return 2;  // before doing anything
  }
  try {
    if (!ctx.repo->revoke_device(name)) {
      std::cerr << "[ERROR] no active device named '" << name << "'\n";
      return 1;
    }
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] revoke failed: " << e.what() << "\n";
    return 1;
  }
  std::cerr << "[OK] device '" << name
            << "' revoked; its wrapped keys were deleted.\n";
  print_revoke_checklist(name);

  switch (mode) {
    case RevokeMode::NoRotate:
      print_incomplete_warning(name);
      return 0;
    case RevokeMode::Rotate:
      // The explicit flag is scripted consent of the same strength as
      // `rotate --yes`.
      return cmd_rotate(ctx, /*assume_yes=*/true);
    case RevokeMode::Prompt: {
      int rc = cmd_rotate(ctx, /*assume_yes=*/false);
      if (rc == 2) {  // declined / consent missing
        print_incomplete_warning(name);
        return 0;
      }
      return rc;
    }
  }
  return 1;  // unreachable
}

int cmd_rewrap(AppContext& ctx) {
  if (!ctx.repo->has_device_tables()) {
    std::cerr << "[ERROR] device tables not migrated — run 'pwmgr migrate' "
                 "first\n";
    return 1;
  }
  try {
    const auto active = ctx.repo->active_devices();
    if (active.empty()) {
      std::cerr << "[WARN] no active devices registered\n";
      return 0;
    }
    sharing::ensure_device_keys_local(active);
    for (const auto& d : active) {
      auto st = sharing::rewrap_all_to_device(
          *ctx.keys, d, ctx.config->recipient_fingerprint(), progress_line);
      std::cerr << "[OK] " << d.name << ": " << st.wrapped << " wrapped, "
                << st.skipped << " already present\n";
    }
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] rewrap failed (safe to re-run): " << e.what()
              << "\n";
    return 1;
  }
}

int cmd_rotate(AppContext& ctx, bool assume_yes) {
  print_backup_warning();
  if (!assume_yes) {
    if (!stdin_is_tty()) {
      std::cerr << "[ERROR] non-interactive rotate requires --yes\n";
      return 2;
    }
    if (prompt_line("Type ROTATE to proceed: ") != "ROTATE") {
      std::cerr << "[WARN] rotation cancelled.\n";
      return 2;
    }
  }
  try {
    auto st = sharing::rotate_all(
        *ctx.keys, ctx.config->recipient_fingerprint(), progress_line);
    std::cerr << "[OK] rotated " << st.rotated << "/" << st.total
              << " entries (" << st.upgraded_v1 << " upgraded v1 -> v2)\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "[ERROR] rotate failed: " << e.what() << "\n";
    return 1;
  }
}

int run_command(const std::vector<std::string>& args, AppContext& ctx) {
  auto usage_err = [](const std::string& msg) {
    std::cerr << "[ERROR] " << msg << "\n\n";
    print_usage(std::cerr);
    return 2;
  };
  const std::string& cmd = args[0];

  if (cmd == "migrate") {
    if (args.size() != 1) return usage_err("migrate takes no arguments");
    return cmd_migrate(ctx);
  }
  if (cmd == "status") {
    if (args.size() != 1) return usage_err("status takes no arguments");
    return cmd_status(ctx);
  }
  if (cmd == "entry") {
    if (args.size() >= 2 && args[1] == "list") {
      if (args.size() == 2) return cmd_entry_list(ctx, false);
      if (args.size() == 3 && args[2] == "--porcelain")
        return cmd_entry_list(ctx, true);
      return usage_err("entry list: only --porcelain is accepted");
    }
    if (args.size() >= 2 && args[1] == "add") {
      std::string note, devices;
      for (std::size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--note" && i + 1 < args.size()) {
          note = args[++i];
        } else if (args[i] == "--devices" && i + 1 < args.size()) {
          devices = args[++i];
        } else {
          return usage_err("entry add: unexpected argument '" + args[i] + "'");
        }
      }
      if (note.empty()) return usage_err("entry add requires --note <s>");
      return cmd_entry_add(ctx, note, devices);
    }
    if (args.size() == 3 && args[1] == "show") {
      try {
        return cmd_entry_show(ctx, std::stoll(args[2]));
      } catch (const std::exception&) {
        return usage_err("entry show: numeric id required");
      }
    }
    if (args.size() == 4 && (args[1] == "grant" || args[1] == "revoke")) {
      std::int64_t id;
      try {
        id = std::stoll(args[2]);
      } catch (const std::exception&) {
        return usage_err("entry " + args[1] + " <id> <device>: numeric id");
      }
      return args[1] == "grant" ? cmd_entry_grant(ctx, id, args[3])
                                : cmd_entry_revoke(ctx, id, args[3]);
    }
    return usage_err("unknown entry subcommand");
  }
  if (cmd == "device") {
    if (args.size() >= 2 && args[1] == "list") {
      if (args.size() == 2) return cmd_device_list(ctx, false);
      if (args.size() == 3 && args[2] == "--porcelain")
        return cmd_device_list(ctx, true);
      return usage_err("device list: only --porcelain is accepted");
    }
    if (args.size() >= 4 && args[1] == "add") {
      const std::string& name = args[2];
      const std::string& path = args[3];
      std::string fpr;
      for (std::size_t i = 4; i < args.size(); ++i) {
        if (args[i] == "--fpr" && i + 1 < args.size()) {
          fpr = args[++i];
        } else {
          return usage_err("device add: unexpected argument '" + args[i] +
                           "'");
        }
      }
      return cmd_device_add(ctx, name, path, fpr);
    }
    if (args.size() >= 3 && args[1] == "revoke") {
      RevokeMode mode = RevokeMode::Prompt;
      for (std::size_t i = 3; i < args.size(); ++i) {
        if (args[i] == "--rotate")
          mode = RevokeMode::Rotate;
        else if (args[i] == "--no-rotate")
          mode = RevokeMode::NoRotate;
        else
          return usage_err("device revoke: unexpected argument '" + args[i] +
                           "'");
      }
      return cmd_device_revoke(ctx, args[2], mode);
    }
    return usage_err("unknown device subcommand");
  }
  if (cmd == "rewrap") {
    if (args.size() != 1) return usage_err("rewrap takes no arguments");
    return cmd_rewrap(ctx);
  }
  if (cmd == "rotate") {
    if (args.size() == 1) return cmd_rotate(ctx, false);
    if (args.size() == 2 && args[1] == "--yes") return cmd_rotate(ctx, true);
    return usage_err("rotate: only --yes is accepted");
  }
  return usage_err("unknown command '" + cmd + "'");
}

}  // namespace pwmgr::cli
