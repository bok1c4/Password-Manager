#pragma once
#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "db/device.h"

namespace pwmgr::config {
struct AppConfig;
}

namespace pwmgr::cli {

struct AppContext;

// The identity `pwmgr migrate` / PWMGR_MIGRATE_V2 registers: name from
// config (effective_device_name), recipient fingerprint, best-effort slurp
// of the exported public key file ("" + [WARN] if unreadable).
db::FoundingDevice make_founding_device(const config::AppConfig& cfg);

void print_usage(std::ostream& out);

// argv subcommand dispatch. Exit codes: 0 success · 1 operation failure
// (stdout stays empty) · 2 usage error / missing non-TTY consent ·
// 3 fingerprint mismatch on device add.
int run_command(const std::vector<std::string>& args, AppContext& ctx);

// Shared flows — the Devices menu screen calls these too (D1: one
// implementation behind both UIs).
int cmd_migrate(AppContext& ctx);
// devices_csv empty -> encrypt to all active devices (default); otherwise to
// the named subset (group encryption).
int cmd_entry_add(AppContext& ctx, const std::string& note,
                  const std::string& devices_csv);
int cmd_entry_show(AppContext& ctx, std::int64_t id);
// Per-entry membership: grant adds a device to one entry's recipient set;
// revoke removes it and ROTATES that entry (the removed device's copy goes stale).
int cmd_entry_grant(AppContext& ctx, std::int64_t id, const std::string& device);
int cmd_entry_revoke(AppContext& ctx, std::int64_t id, const std::string& device);
// CMS read views. entry_list: every entry + the devices that can decrypt it
// (porcelain: id<TAB>ver<TAB>note<TAB>dev1,dev2). status: device/entry counts,
// per-device decryptable coverage, and a deployment-readiness verdict.
int cmd_entry_list(AppContext& ctx, bool porcelain);
int cmd_status(AppContext& ctx);
int cmd_device_list(AppContext& ctx, bool porcelain);
// expected_fpr may be "" -> prompted on a TTY, usage error otherwise.
int cmd_device_add(AppContext& ctx, const std::string& name,
                   const std::string& pubkey_path, std::string expected_fpr);
enum class RevokeMode { Prompt, Rotate, NoRotate };
int cmd_device_revoke(AppContext& ctx, const std::string& name, RevokeMode mode);
int cmd_rewrap(AppContext& ctx);
// assume_yes carries scripted consent (rotate --yes / revoke --rotate).
// Returns 2 when consent is missing or declined.
int cmd_rotate(AppContext& ctx, bool assume_yes);

}  // namespace pwmgr::cli
