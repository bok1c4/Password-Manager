#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "commands.h"
#include "config/config.h"
#include "crypto/encryptor.h"
#include "crypto/gpg.h"
#include "db/repository.h"
#include "screen.h"
#include "screens.h"
#include "sharing/rewrap.h"
#include "terminal.h"

int main(int argc, char** argv) {
  using namespace pwmgr;

  const std::vector<std::string> args(argv + 1, argv + argc);
  if (!args.empty() &&
      (args[0] == "help" || args[0] == "--help" || args[0] == "-h")) {
    cli::print_usage(std::cout);  // before config/DB: help must always work
    return 0;
  }

  // 1) Resolve ONE absolute config path; fail loud (never invent a default).
  config::ConfigManager cfgmgr(config::ConfigManager::default_path());
  config::AppConfig cfg;
  try {
    cfg = cfgmgr.load();
  } catch (const std::exception& e) {
    std::cerr << "[FATAL] " << e.what() << "\n"
              << "        Config path: " << cfgmgr.path() << "\n";
    return 1;
  }

  // 2) Connect (RAII connection inside Repository); fail loud on error.
  const std::string conn = config::effective_db_connection(cfg);
  std::unique_ptr<db::Repository> repo;
  try {
    repo = std::make_unique<db::Repository>(conn);
  } catch (const std::exception& e) {
    std::cerr << "[FATAL] Database connection failed: " << e.what() << "\n";
    return 1;
  }

  // 3) Additive, idempotent migration (adds enc_version; never destructive).
  //    Migration v2 (devices/password_keys) is OPT-IN ONLY: `pwmgr migrate`
  //    or PWMGR_MIGRATE_V2=1 — a routine launch never writes new schema.
  try {
    repo->apply_migrations();
    if (const char* v2 = std::getenv("PWMGR_MIGRATE_V2");
        v2 && std::string(v2) == "1") {
      repo->apply_migrations_v2(cli::make_founding_device(cfg));
    }
  } catch (const std::exception& e) {
    std::cerr << "[WARN] Could not apply migrations (continuing read-only): "
              << e.what() << "\n";
  }

  // 4) Warn early if the recipient's secret key is absent (decrypt would fail).
  const std::string recipient = cfg.recipient_fingerprint();
  if (!crypto::gpg_has_secret_key(recipient)) {
    std::cerr << "[WARN] No secret key for recipient " << recipient
              << " in the GnuPG keyring; decryption will not work.\n";
  }

  crypto::Encryptor enc(recipient);
  sharing::RepositoryKeyStore keys(*repo);
  cli::AppContext ctx{&cfg, &cfgmgr, repo.get(), &enc, &keys};

  // argv subcommand mode (scriptable surface; the test harness drives this).
  if (!args.empty()) return cli::run_command(args, ctx);

  cli::ScreenManager mgr;
  mgr.push(std::make_unique<cli::MainMenuScreen>(&mgr, &ctx));

  while (!mgr.empty()) {
    cli::Screen* cur = mgr.current();
    if (!cur) break;
    cur->render();

    std::string line;
    if (!std::getline(std::cin, line)) break;  // EOF
    cur->handle_input(line);
    cli::clear_screen();
  }

  std::cout << "\n[INFO] Goodbye.\n";
  return 0;
}
