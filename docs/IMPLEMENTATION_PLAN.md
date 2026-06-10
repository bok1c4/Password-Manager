# Multi-Device Feature — Unified Implementation Plan

<!--toc:start-->

- [Multi-Device Feature — Unified Implementation Plan](#multi-device-feature-unified-implementation-plan) - [Cross-stream reconciliations (binding decisions)](#cross-stream-reconciliations-binding-decisions)
  - [§1 Change inventory](#1-change-inventory)
  - [§2 Work-stream: Data layer (schema, migration v2, repository API)](#2-work-stream-data-layer-schema-migration-v2-repository-api)
    - [2.1 `scripts/schema.sql`](#21-scriptsschemasql)
    - [2.2 `src/core/db/device.h` / `device.cpp` (new)](#22-srccoredbdeviceh-devicecpp-new)
    - [2.3 `src/core/db/repository.h` — declarations](#23-srccoredbrepositoryh-declarations)
    - [2.4 `src/core/db/repository.cpp` — key bodies](#24-srccoredbrepositorycpp-key-bodies)
    - [2.5 `src/core/config/config.{h,cpp}`](#25-srccoreconfigconfighcpp)
    - [2.6 `src/cli/main.cpp` (data-layer half; argv dispatch is §3.6)](#26-srcclimaincpp-data-layer-half-argv-dispatch-is-36)
    - [2.7 Data-layer tests](#27-data-layer-tests)
  - [§3 Work-stream: Crypto engine + CLI](#3-work-stream-crypto-engine-cli)
    - [3.1 `src/core/crypto/gpg.{h,cpp}`](#31-srccorecryptogpghcpp)
    - [3.2 `src/core/sharing/rewrap.h` — the KeyStore seam](#32-srccoresharingrewraph-the-keystore-seam)
    - [3.3 `src/core/sharing/rewrap.cpp` — engines](#33-srccoresharingrewrapcpp-engines)
    - [3.4 Read path (exact call sites)](#34-read-path-exact-call-sites)
    - [3.5 Write path (exact call sites)](#35-write-path-exact-call-sites)
    - [3.6 `src/cli/main.cpp` + `src/cli/commands.{h,cpp}` — argv dispatch](#36-srcclimaincpp-srcclicommandshcpp-argv-dispatch)
    - [3.7 `DevicesScreen` (menu `[5] Devices`)](#37-devicesscreen-menu-5-devices)
    - [3.8 Crypto/CLI tests](#38-cryptocli-tests)
  - [§4 Work-stream: Network scripts (Phases 3+4 tooling)](#4-work-stream-network-scripts-phases-34-tooling)
    - [4.1 `scripts/gen-db-certs.sh`](#41-scriptsgen-db-certssh)
    - [4.2 `scripts/onion-auth-keygen.sh`](#42-scriptsonion-auth-keygensh)
    - [4.3 `scripts/setup-onion.sh`](#43-scriptssetup-onionsh)
    - [4.4 `scripts/templates/pwmgr-onion-forward.service`](#44-scriptstemplatespwmgr-onion-forwardservice)
    - [4.5 `scripts/rotate-db-password.sh`](#45-scriptsrotate-db-passwordsh)
    - [4.6 `scripts/export-key.sh` (comment-only)](#46-scriptsexport-keysh-comment-only)
    - [4.7 `tests/scripts/test_network_scripts.sh` + Makefile `test-scripts`](#47-testsscriptstestnetworkscriptssh-makefile-test-scripts)
    - [4.8 Doc edits](#48-doc-edits)
  - [§5 Work-stream: Test harness (Phase 5 rehearsals)](#5-work-stream-test-harness-phase-5-rehearsals)
    - [5.1 `docker/compose.test.yml`](#51-dockercomposetestyml)
    - [5.2 `docker/device-entrypoint.sh`](#52-dockerdevice-entrypointsh)
    - [5.3 `scripts/test-two-devices.sh`](#53-scriptstest-two-devicessh)
    - [5.4 `scripts/staging-rehearsal.sh`](#54-scriptsstaging-rehearsalsh)
    - [5.5 `scripts/restore.sh` (modified)](#55-scriptsrestoresh-modified)
    - [5.6 `docker/compose.net.yml` + `scripts/test-net-negative.sh`](#56-dockercomposenetyml-scriptstest-net-negativesh)
    - [5.7 Makefile + docs](#57-makefile-docs)
  - [§6 Commit/PR sequence](#6-commitpr-sequence)
  - [§7 Definition of done per phase + what stays manual](#7-definition-of-done-per-phase-what-stays-manual)
  - [§8 Decisions (resolved 2026-06-11 — defaults confirmed)](#8-decisions-resolved-2026-06-11-defaults-confirmed)
  <!--toc:end-->

**STATUS: IMPLEMENTED 2026-06-11** (commits `c6f16ae..c943eb3` + the
FK-reset test fix). All 18 commits landed with `make`/`make test` green;
gated suite green on a throwaway DB; `make test-scripts` 20/20;
`make test-devices` 5/5 lifecycle assertions in the two-container rig;
`make test-net` 41–45. **The production DB is untouched** — migration v2
runs only via `pwmgr migrate` (Phase 6, backup first). Remaining for the
user: §7 manual steps (prod migrate, real second device, network phases).
Plan as approved below; deviations are noted in the commit messages (the
backfill additionally pins to the lowest-id device).
Date: 2026-06-11.
Architecture authority: [MULTI_DEVICE_PLAN.md](MULTI_DEVICE_PLAN.md) (schema, lifecycle, phases, decisions D1–D5) and [REMOTE.md](REMOTE.md) (LAN + Tor onion spec). This document is the synthesized, reviewed work plan across the four streams (data layer, crypto+CLI, network scripts, test harness), with every adversarial-review issue resolved. Notable review-driven changes are marked **(fixed in review: …)**.

Standing invariants (restated, binding on every commit):

- The 13 existing v1 rows stay decryptable at every commit.
- All schema changes additive; `passwords` never altered/rewritten in place.
- `passwords.aes_key` kept and still written as the legacy founding wrap (D5).
- Backup before any prod write. Secret keys never leave their device. Revoke without rotation = incomplete.
- Build via the Makefile (`make`, `make test`) — cmake is not installed. Founding fingerprint: `29974BE04FCC7C31C4D1493730D6A019C21A600C`. Envelope: v1 = base64(IV‖AES-256-CBC); v2 = `"v2:"`‖base64(nonce‖GCM‖tag).

### Cross-stream reconciliations (binding decisions)

| Topic                      | Decision                                                                                                                                                                                                                                                                                                                                                                                              |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Migration v2 trigger       | **Never auto-runs.** `Repository::apply_migrations()` stays v1-only (byte-identical body). New `apply_migrations_v2(const FoundingDevice&)` runs only via the `pwmgr migrate` subcommand or `PWMGR_MIGRATE_V2=1` env. (fixed in review: unguarded prod write on every launch — the data-layer blocker; also satisfies the harness's `pwmgr migrate` contract and kills the deviceB self-enroll risk.) |
| Wrap struct                | One struct, `pwmgr::db::WrappedKey { std::int64_t device_id; std::string armored; }` in `device.h`, used by Repository, KeyStore and engines. (Stream A `WrappedKey` / Stream B `DeviceWrap`+`Wrap` merged.)                                                                                                                                                                                          |
| Rotate-support repo method | Named `replace_entry_keys(...)` everywhere (Stream B's `replace_entry` renamed). KeyStore method names are identical to Repository's, so `RepositoryKeyStore` is pure delegation.                                                                                                                                                                                                                     |
| Revoke semantics           | `Repository::revoke_device(name)` sets status/revoked_at **and deletes the device's `password_keys` rows in the same transaction** (Stream A behavior wins). Stream B's `delete_wraps_for_device` is **dropped**.                                                                                                                                                                                     |
| Fingerprint normalization  | Single implementation `pwmgr::db::normalize_fingerprint` / `is_valid_fingerprint` (device.h). `sharing::normalize_fingerprint` duplicate dropped; CLI uses the db one.                                                                                                                                                                                                                                |
| CLI surface                | `pwmgr migrate` · `entry add --note <s>` (password on stdin, prints id) · `entry show <id>` · `device list [--porcelain]` · `device add <name> <pubkey.asc> --fpr <40hex>` · `device revoke <name> [--rotate\|--no-rotate]` · `rewrap` · `rotate [--yes]` · `help`. Harness uses exactly these (its `--expect-fpr`/`--porcelain` drafts renamed/adopted).                                             |
| Exit codes                 | 0 success · 1 operation failure (incl. decrypt fail; stdout stays empty) · 2 usage error / missing non-TTY consent · 3 fingerprint mismatch on `device add`.                                                                                                                                                                                                                                          |
| D5 legacy recipient        | Founding device if active, else lowest-`id` active device; rotate prints `[INFO]` when the fallback triggers (see §8 Q1).                                                                                                                                                                                                                                                                             |
| `gen-db-certs.sh` CLI      | Positional `<host> [extra-san…]` + `PWMGR_CERT_DIR` env (Stream C contract). The net-negative rig calls it that way (Stream D's invented `--out/--host` flags dropped).                                                                                                                                                                                                                               |

---

## §1 Change inventory

| Path                                            | Stream      | New/Mod | Summary                                                                                                                                                                                       |
| ----------------------------------------------- | ----------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scripts/schema.sql`                            | data        | mod     | Append `devices` + `password_keys` DDL (plan §2) for fresh installs; refresh stale header comment                                                                                             |
| `src/core/db/device.h`                          | data        | new     | `Device`, `FoundingDevice`, `WrappedKey`, `is_valid_fingerprint()`, `normalize_fingerprint()`                                                                                                 |
| `src/core/db/device.cpp`                        | data        | new     | Fingerprint function bodies                                                                                                                                                                   |
| `src/core/db/repository.h`                      | data        | mod     | `apply_migrations_v2()`, `has_device_tables_` probe, full device/wrap API (incl. engine-support methods)                                                                                      |
| `src/core/db/repository.cpp`                    | data        | mod     | Migration v2 (one txn, empty-table-guarded founding insert), probe, all API bodies                                                                                                            |
| `src/core/config/config.h`                      | data        | mod     | `AppConfig::device_name` + `effective_device_name()`                                                                                                                                          |
| `src/core/config/config.cpp`                    | data        | mod     | Optional `device_name` parse/serialize + fallback accessor                                                                                                                                    |
| `src/core/crypto/gpg.h`                         | crypto      | mod     | `gpg_import_public_key()` (pre-inspecting), `gpg_export_public_key()`                                                                                                                         |
| `src/core/crypto/gpg.cpp`                       | crypto      | mod     | Implementations (gpgme keylist-from-data, import, export)                                                                                                                                     |
| `src/core/sharing/rewrap.h`                     | crypto      | new     | `KeyStore` seam, `RepositoryKeyStore`, enroll/rotate engines, write-path helpers                                                                                                              |
| `src/core/sharing/rewrap.cpp`                   | crypto      | new     | Engine implementations                                                                                                                                                                        |
| `src/cli/commands.h`                            | crypto      | new     | `run_command()` dispatch + shared `cmd_*` flows (used by argv and menu)                                                                                                                       |
| `src/cli/commands.cpp`                          | crypto      | new     | Subcommand implementations, consent prompts, progress                                                                                                                                         |
| `src/cli/screen.h`                              | crypto      | mod     | `AppContext` gains `sharing::KeyStore* keys`                                                                                                                                                  |
| `src/cli/screens.h`                             | crypto      | mod     | `DevicesScreen` declaration                                                                                                                                                                   |
| `src/cli/screens.cpp`                           | crypto      | mod     | Menu `[5] Devices`; read path → `wrapped_key_for`; write path → sharing helpers; `DevicesScreen`                                                                                              |
| `src/cli/main.cpp`                              | data+crypto | mod     | argv dispatch; default startup stays v1-migration-only; `FoundingDevice` assembly helper                                                                                                      |
| `scripts/gen-db-certs.sh`                       | net         | new     | Mini-CA + Postgres server cert w/ SAN; 0600 keys; idempotent; refuses partial overwrite                                                                                                       |
| `scripts/onion-auth-keygen.sh`                  | net         | new     | Per-device x25519 onion client-auth pair; prints `.auth`/`.auth_private` lines; shreds temps                                                                                                  |
| `scripts/setup-onion.sh`                        | net         | new     | Idempotent server torrc block + HS dir; `--enable` gates systemctl; manual fallback                                                                                                           |
| `scripts/rotate-db-password.sh`                 | net         | new     | Dry-run by default; `--apply` = backup → ALTER ROLE → `~/.pgpass` → strip config password; crash-recovery file                                                                                |
| `scripts/templates/pwmgr-onion-forward.service` | net         | new     | Client socat forward, systemd **user** unit template (`@ONION_ADDR@`/`@LOCAL_PORT@`/`@SOCKS_PORT@`)                                                                                           |
| `scripts/export-key.sh`                         | net         | mod     | Comment-only: add `hs_ed25519_secret_key` offline-backup paragraph (REMOTE.md §3.3)                                                                                                           |
| `tests/scripts/test_network_scripts.sh`         | net         | new     | Sandboxed bash harness for the four scripts (PATH stubs for psql/pg_dump/systemctl)                                                                                                           |
| `docs/REMOTE.md`                                | net         | mod     | Replace "Phase 4 deliverable" forward-refs with committed script paths                                                                                                                        |
| `docs/ROTATION.md`                              | net         | mod     | Point manual rotation section at `rotate-db-password.sh`; retitle "(recommended before any network tier)" — the real password was never committed, only the dummy `temp123` is in git history |
| `docker/compose.test.yml`                       | harness     | new     | `db` (pg18, `pwmgr_test`, no host ports) + `deviceA`/`deviceB` from existing Dockerfile                                                                                                       |
| `docker/device-entrypoint.sh`                   | harness     | new     | Ephemeral GPG key, pubkey/fpr on `/shared`, config.json, `pwmgr` symlink, idle                                                                                                                |
| `docker/compose.net.yml`                        | harness     | new     | Throwaway TLS Postgres (`db-tls`) + psql `client` for Tier-1 negatives                                                                                                                        |
| `scripts/test-two-devices.sh`                   | harness     | new     | Five-assertion two-device lifecycle orchestrator (3 seeded entries)                                                                                                                           |
| `scripts/staging-rehearsal.sh`                  | harness     | new     | Restore latest dump → `pwmgr_test`; `pwmgr migrate`; bit-identity + backfill + idempotency checks                                                                                             |
| `scripts/test-net-negative.sh`                  | harness     | new     | Plaintext/wrong-CA/wrong-password refused + verify-full positive controls; manual onion checklist                                                                                             |
| `scripts/restore.sh`                            | harness     | mod     | `PWMGR_RESTORE_DB` override (must contain `test`, never `pwmgr`)                                                                                                                              |
| `Makefile`                                      | net+harness | mod     | New phony targets `test-scripts`, `test-devices`, `test-staging`, `test-net`; `make test` unchanged                                                                                           |
| `docs/MULTI_DEVICE_PLAN.md`                     | harness     | mod     | Doc-only pointers in §5 items 3–5 to the make entry points                                                                                                                                    |
| `tests/test_device.cpp`                         | data        | new     | Plain: fingerprint validation/normalization                                                                                                                                                   |
| `tests/test_config.cpp`                         | data        | mod     | Plain: `device_name` round-trip + fallback chain                                                                                                                                              |
| `tests/test_repository_devices.cpp`             | data        | new     | Gated: migration v2 idempotency, read shapes, revoke, atomic rotate support, bit-identical `passwords`                                                                                        |
| `tests/test_repository.cpp`                     | crypto      | mod     | Gated: entry+keys atomicity, `entry_ids_wrapped_for`, table-absent degradation                                                                                                                |
| `tests/fake_keystore.h`                         | crypto      | new     | `InMemoryKeyStore` for ungated engine tests                                                                                                                                                   |
| `tests/gpg_test_home.h`                         | crypto      | new     | Ephemeral-`GNUPGHOME` RAII fixture (batch `%no-protection` keygen)                                                                                                                            |
| `tests/test_gpg_enroll.cpp`                     | crypto      | new     | Ungated: import/export, swapped-key detection, enroll round-trip, resume, rotate, write path                                                                                                  |

Makefile wildcards (`src/core/*/*.cpp`, `src/cli/*.cpp`, `tests/*.cpp`) pick up every new `.cpp` automatically; no build-file edits beyond the phony targets. Legacy tree (`src/main.cpp`, `src/utils/`, `src/screens/`, `include/`) untouched.

---

## §2 Work-stream: Data layer (schema, migration v2, repository API)

### 2.1 `scripts/schema.sql`

Append after the `schema_migrations` block the verbatim DDL from MULTI_DEVICE_PLAN.md §2 (`devices`, `password_keys`); update the header comment ("startup migration only ADDS enc_version") to note that **migration v2 exists but only runs via `pwmgr migrate`**.

### 2.2 `src/core/db/device.h` / `device.cpp` (new)

```cpp
namespace pwmgr::db {

struct Device {            // one row of `devices`; enrolled_at = ::text, display-only
  std::int64_t id = 0;
  std::string name, fingerprint /*40 upper hex*/, public_key, status, enrolled_at;
};

struct FoundingDevice {    // identity migration v2 registers; built by the CLI layer
  std::string name;               // AppConfig::effective_device_name()
  std::string fingerprint;        // AppConfig::recipient_fingerprint()
  std::string public_key_armored; // matching KeyRef file contents; "" if unreadable
};

// One armored GPG wrap destined for password_keys (shared by Repository,
// KeyStore and the sharing engines — single definition, no per-layer clones).
struct WrappedKey { std::int64_t device_id; std::string armored; };

bool is_valid_fingerprint(std::string_view fpr);          // exactly 40 hex
std::string normalize_fingerprint(std::string_view fpr);  // strip spaces, upper; "" if invalid
}
```

Bodies as in the stream spec (`std::isxdigit` loop; normalize strips ASCII spaces, uppercases, validates).

### 2.3 `src/core/db/repository.h` — declarations

`#include "db/device.h"` after the pqxx include. The existing `void apply_migrations();` declaration and body stay **byte-identical** (v1 only). New:

```cpp
  // v2 (additive, idempotent, ONE transaction): creates devices+password_keys,
  // registers `founding` ONLY IF the devices table is empty (cross-stream
  // guard: an enrolled device's `migrate` must never self-enroll), backfills
  // password_keys from passwords.aes_key (copies, never moves).
  // NEVER called from normal startup — only `pwmgr migrate` / PWMGR_MIGRATE_V2=1.
  void apply_migrations_v2(const FoundingDevice& founding);

  // ---- multi-device API. Degradation contract on a pre-migration DB
  // (has_device_tables_ == false), method by method:           (fixed in
  // review: the old blanket "all no-op/fallback" comment was false)
  //   list_devices/active_devices/all_entry_ids-wrapped views -> empty
  //   founding_device()                                       -> nullopt
  //   wrapped_key_for()                  -> falls back to passwords.aes_key
  //   revoke_device()                                         -> false
  //   add_device()/insert_wrapped_key()  -> throw std::runtime_error
  //                                         ("device tables not migrated")
  //   replace_entry_keys()/insert_entry_with_keys() with EMPTY wraps
  //                                      -> legacy-equivalent SQL; with
  //                                         non-empty wraps -> throw (never
  //                                         silently drop the access matrix)
  bool has_device_tables() const { return has_device_tables_; }
  std::vector<Device> list_devices();          // ORDER BY id
  std::vector<Device> active_devices();        // status='active' ORDER BY id
  std::optional<Device> founding_device();     // lowest devices.id
  std::int64_t add_device(const Device& d);    // validates fingerprint; returns id
  bool revoke_device(std::string_view name);   // status+revoked_at+DELETE wraps, one txn;
                                               // false if no active device of that name
  std::optional<std::string> wrapped_key_for(std::int64_t password_id,
                                             std::string_view fingerprint);
  void insert_wrapped_key(std::int64_t password_id, std::int64_t device_id,
                          std::string_view wrapped_armored);   // ON CONFLICT DO NOTHING
  std::vector<std::int64_t> all_entry_ids();                   // passwords.id ASC
  std::vector<std::int64_t> entry_ids_wrapped_for(std::int64_t device_id);
  void replace_entry_keys(std::int64_t id, std::string_view password_blob,
                          std::string_view founding_wrap_armored, int enc_version,
                          const std::vector<WrappedKey>& wraps);   // one txn
  std::int64_t insert_entry_with_keys(std::string_view password_blob,
                                      std::string_view founding_wrap_armored,
                                      std::string_view note, int enc_version,
                                      const std::vector<WrappedKey>& wraps); // one txn
private:
  bool detect_device_tables();        // information_schema probe, both tables required
  bool has_device_tables_ = false;
```

### 2.4 `src/core/db/repository.cpp` — key bodies

Constructor gains `has_device_tables_ = detect_device_tables();` after the enc_version probe. Probe mirrors `detect_enc_version()` (`SELECT 1 FROM information_schema.tables WHERE table_name IN ('devices','password_keys') HAVING count(*)=2`, catch-all → false).

**Migration v2** — separate method, one `pqxx::work`, `SET LOCAL lock_timeout='5s'` / `statement_timeout='30s'`, then:

1. `CREATE TABLE IF NOT EXISTS devices (...)`, `CREATE TABLE IF NOT EXISTS password_keys (...)` (DDL exactly as plan §2).
2. Founding insert, **guarded by empty table** (fixed in review: harness R1 — unconditional insert would self-enroll device B):

   ```sql
   INSERT INTO devices (name, fingerprint, public_key)
   SELECT $1, $2, $3 WHERE NOT EXISTS (SELECT 1 FROM devices)
   ON CONFLICT (fingerprint) DO NOTHING;
   ```

   (fingerprint pre-normalized via `normalize_fingerprint`; invalid/empty → skip insert+backfill, tables still created). A _name_ collision with a different fingerprint still throws — caught as `[WARN]` at the interactive call site, hard failure under `pwmgr migrate`.
3. Idempotent backfill (copies, never moves):

   ```sql
   INSERT INTO password_keys (password_id, device_id, wrapped_key)
   SELECT p.id, d.id, p.aes_key FROM passwords p CROSS JOIN devices d
   WHERE d.fingerprint=$1 ON CONFLICT (password_id, device_id) DO NOTHING;
   ```

4. `INSERT INTO schema_migrations(version) VALUES (2) ON CONFLICT DO NOTHING;` → commit → `has_device_tables_ = true;`.

**API bodies** follow the house idioms (string_view → named std::string locals, one `pqxx::work`/method, `pqxx::params{}`, `convert_from(...,'UTF8')` for bytea reads, plain text params for armored writes — identical byte-faithfulness argument as `aes_key`). Specifics, with review fixes folded in:

- `add_device` / `insert_wrapped_key`: `if (!has_device_tables_) throw std::runtime_error("device tables not migrated — run 'pwmgr migrate' first");` then validated insert (`add_device` throws `std::invalid_argument` on a bad fingerprint). **(fixed in review: previously leaked raw pqxx `undefined_table`.)**
- `revoke_device`: `if (!has_device_tables_) return false;` then one txn: `UPDATE devices SET status='revoked', revoked_at=now() WHERE name=$1 AND status='active' RETURNING id` — empty → return false (txn dtor aborts) — then `DELETE FROM password_keys WHERE device_id=$1`, commit, true.
- `wrapped_key_for`: if migrated and fpr valid, `SELECT convert_from(pk.wrapped_key,'UTF8') ... JOIN devices d ... WHERE pk.password_id=$1 AND d.fingerprint=$2 AND d.status='active'`; one row → return it. Else unconditional legacy fallback `SELECT convert_from(aes_key,'UTF8') FROM passwords WHERE id=$1`; no row → nullopt. (Fallback returns the founding wrap even for unknown fingerprints — undecryptable for them by design; access checks belong to the join, documented in the header.)
- `replace_entry_keys`: `if (!has_device_tables_ && !wraps.empty()) throw std::runtime_error("device tables not migrated; refusing to drop per-device wraps");` **(fixed in review: silent truncation of the access matrix)**. One txn: `UPDATE passwords SET password=$1, aes_key=$2[, enc_version=$3] WHERE id=$N RETURNING id` — **throw if no row matched** (matches the `delete_entry` RETURNING idiom) **(fixed in review: empty-wraps rotation of a vanished id silently committed nothing)** — then `DELETE FROM password_keys WHERE password_id=$1` and plain INSERTs per wrap (no ON CONFLICT: a duplicate device_id in `wraps` is a caller bug and must abort loudly).
- `insert_entry_with_keys`: same non-empty-wraps guard; one txn, `INSERT ... RETURNING id` (+`enc_version` when probed), then per-wrap INSERTs.
- `entry_ids_wrapped_for`: `SELECT password_id FROM password_keys WHERE device_id=$1 ORDER BY password_id` (sorted — the enroll engine binary-searches it); `{}` pre-migration.
- `founding_device`: `SELECT ... FROM devices ORDER BY id ASC LIMIT 1`; nullopt pre-migration.

Add `#include <stdexcept>`.

### 2.5 `src/core/config/config.{h,cpp}`

- `AppConfig::device_name` (optional key) + `effective_device_name()`: `device_name` → `username` → `"founding-device"`. Never empty.
- `load()`: `c.device_name = j.value("device_name", "");` after the username line — no new validation (old configs keep loading). `save()`: write only when non-empty, inserted after `j["username"] = c.username;` at **config.cpp:83** (fixed in review: spec cited :84, which is the `db_connection` line — apply by anchor text, not number).

### 2.6 `src/cli/main.cpp` (data-layer half; argv dispatch is §3.6)

Startup step 3 stays exactly as today: `repo->apply_migrations();` inside the try/WARN block — **v1 only, no prod write**. Immediately after, opt-in v2 (fixed in review: the data-layer blocker — the old spec ran v2 unconditionally on every launch of the daily binary against `dbname=pwmgr`, an un-backed-up prod write):

```cpp
    if (const char* v2 = std::getenv("PWMGR_MIGRATE_V2"); v2 && std::string(v2) == "1") {
      repo->apply_migrations_v2(make_founding_device(cfg));   // same try/WARN block
    }
```

File-local helper `make_founding_device(cfg)`: name = `effective_device_name()`, fingerprint = `recipient_fingerprint()`, `public_key_armored` = best-effort slurp of the matching `public_keys[]` KeyRef file (binary ifstream; `""` + `[WARN]` if unreadable — `devices.public_key` is completed at real `device add` time; nothing reads the local device's own column). The `pwmgr migrate` subcommand (§3.6) calls `apply_migrations()` + `apply_migrations_v2(...)` and **hard-fails** (no WARN-and-continue).

### 2.7 Data-layer tests

Plain (`make test`):

- `tests/test_device.cpp`: 40-hex accept (upper+lower), reject 39/41/empty/`G`/embedded-space; `normalize_fingerprint` of the gpg space-grouped display form == canonical; invalid → `""`.
- `tests/test_config.cpp` additions: `device_name` save/load round-trip; fallback chain (unset→username→`"founding-device"`); legacy JSON without the key loads.

Gated (`tests/test_repository_devices.cpp`, `PWMGR_TEST_DB` + dbname guard copied verbatim from **tests/test_repository.cpp:18-26** (fixed in review: anchor was off by one)). Schema reset **before constructing `Repository`** (both probes run in the ctor), in FK-dependency order with a comment stating why (fixed in review: previous order failed `DROP TABLE passwords` on every run after the first migration):

```sql
DROP TABLE IF EXISTS password_keys CASCADE;
DROP TABLE IF EXISTS devices CASCADE;
DROP TABLE IF EXISTS passwords CASCADE;
DROP TABLE IF EXISTS user_public_keys, schema_migrations CASCADE;
```

| Test (commit it lands in — see §6)                                      | Asserts                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `devices: unmigrated DB probes false` (A3)                              | fresh base schema → `has_device_tables()==false`; raw-SQL check that neither table exists. **(fixed in review: the old commit-3 test referenced `list_devices`/`wrapped_key_for`, which are commit-4 API — wouldn't compile.)**                                                                                                                                                                                 |
| `devices: migration v2 registers founding + backfills; idempotent` (A3) | seed 2 legacy rows; snapshot `SELECT id,password,convert_from(aes_key,'UTF8'),note FROM passwords ORDER BY id`; `apply_migrations_v2(founding)` → 1 active device (normalized fpr), 2 `password_keys` rows, wrap content == aes_key; run again → still 1/2; second device's `apply_migrations_v2` (different founding) inserts **no** new device (empty-table guard); `passwords` snapshot identical throughout |
| `devices: unmigrated degradation` (A4)                                  | pre-migration repo: `list_devices()` empty, `wrapped_key_for(id, FPR)` returns the seeded `aes_key` sentinel, `revoke_device` false, `add_device`/`insert_wrapped_key` throw `runtime_error`, `replace_entry_keys` with non-empty wraps throws                                                                                                                                                                  |
| `devices: three read shapes` (A4)                                       | legacy-only / new-only / both, per the plan §5.2 — fallback sentinel, per-device wrap, backfilled copy                                                                                                                                                                                                                                                                                                          |
| `devices: insert_wrapped_key idempotent` (A4)                           | double insert → 1 row, no throw                                                                                                                                                                                                                                                                                                                                                                                 |
| `devices: revoke deletes rows and falls back` (A4)                      | revoked status, excluded from `active_devices`, wraps gone, `wrapped_key_for(fprB)` → legacy sentinel; unknown/already-revoked name → false                                                                                                                                                                                                                                                                     |
| `devices: replace_entry_keys atomic, complete, loud` (A4)               | new blob/wrap/version visible, exactly the given wraps remain; nonexistent id → throws (RETURNING guard)                                                                                                                                                                                                                                                                                                        |
| `devices: add_device rejects malformed fingerprint` (A4)                | 39 chars → `std::invalid_argument`                                                                                                                                                                                                                                                                                                                                                                              |

---

## §3 Work-stream: Crypto engine + CLI

### 3.1 `src/core/crypto/gpg.{h,cpp}`

`gpg_encrypt_to_fingerprint(plaintext, fpr)` already exists (gpg.h:16, ALWAYS_TRUST, rejects invalid_recipients) — unchanged. New:

```cpp
// Pre-inspects the armored data WITHOUT importing (gpgme_op_keylist_from_data):
// rejects secret-key material, multiple primary keys, or no key BEFORE any
// keyring write; then imports and returns the 40-char primary fingerprint.
std::string gpg_import_public_key(std::string_view armored);
std::string gpg_export_public_key(std::string_view fingerprint);  // armored; throws if absent/empty
```

**(fixed in review: the old flow checked `secret_read` only AFTER `gpgme_op_import`, so accidentally-fed secret keys were already written into the real keyring before the "refusal" — touching the secret-keys-never-leave-their-device invariant. Pre-inspection also detects a fingerprint mismatch before import, eliminating the old R7 "wrong key left in keyring" cleanup hint.)** Implementation: `gpgme_op_keylist_from_data(ctx, data, 0)` loop — count primary keys, check `key->secret`, capture `key->fpr`; then a fresh `Data` for `gpgme_op_import`; verify the import result reports the same fingerprint. Fallback if `keylist_from_data` proves unavailable at build time: keep post-import checks but print explicit cleanup commands (`gpg --delete-secret-keys <fpr>; gpg --delete-key <fpr>`) on the secret-material error. Export via `gpgme_op_export(..., 0, out)`. Existing `Ctx`/`Data`/`read_all` RAII helpers and error style reused; `#include <algorithm>`, `<vector>`.

### 3.2 `src/core/sharing/rewrap.h` — the KeyStore seam

As in the stream spec, with reconciled names/types:

```cpp
namespace pwmgr::sharing {
using ProgressFn = std::function<void(std::size_t, std::size_t, const std::string&)>;

class KeyStore {                       // prod = RepositoryKeyStore; tests = InMemoryKeyStore
 public:
  virtual ~KeyStore() = default;
  virtual std::vector<db::Device> active_devices() = 0;
  virtual std::optional<db::Device> founding_device() = 0;
  virtual std::vector<std::int64_t> all_entry_ids() = 0;
  virtual std::vector<std::int64_t> entry_ids_wrapped_for(std::int64_t device_id) = 0;
  virtual std::string wrapped_key_for(std::int64_t id, std::string_view fpr) = 0; // throws if entry gone
  virtual db::Entry get_entry(std::int64_t id) = 0;
  virtual void insert_wrapped_key(std::int64_t id, std::int64_t device_id,
                                  std::string_view armored) = 0;                  // idempotent
  virtual std::int64_t insert_entry_with_keys(std::string_view blob,
      std::string_view founding_wrap_armored, std::string_view note, int enc_version,
      const std::vector<db::WrappedKey>& wraps) = 0;                              // one txn
  virtual void replace_entry_keys(std::int64_t id, std::string_view blob,
      std::string_view founding_wrap_armored, int enc_version,
      const std::vector<db::WrappedKey>& wraps) = 0;                              // one txn
};
// RepositoryKeyStore: every override is a one-line delegate to db::Repository
// (names identical by design); wrapped_key_for converts repo nullopt -> throw.

struct RewrapStats { std::size_t total=0, wrapped=0, skipped=0; };
struct RotateStats { std::size_t total=0, rotated=0, upgraded_v1=0; };

RewrapStats rewrap_all_to_device(KeyStore&, const db::Device& target,
                                 std::string_view my_fingerprint, const ProgressFn& = {});
RotateStats rotate_all(KeyStore&, std::string_view my_fingerprint, const ProgressFn& = {});
std::int64_t store_new_entry(KeyStore&, std::string_view my_fingerprint,
                             std::string_view plaintext, std::string_view note);
void replace_entry_password(KeyStore&, std::string_view my_fingerprint,
                            std::int64_t id, std::string_view plaintext);
void ensure_device_keys_local(const std::vector<db::Device>& devices);
}
```

`ensure_device_keys_local` **unconditionally** calls `gpg_import_public_key(d.public_key)` for every device and requires the returned fingerprint == `normalize_fingerprint(d.fingerprint)` — import is idempotent and the tamper check now runs on **every** call. **(fixed in review: the old spec needed a "not in keyring" probe that didn't exist — no `gpg_has_public_key` helper; the unconditional-import variant is simpler and stronger.)**

### 3.3 `src/core/sharing/rewrap.cpp` — engines

Exactly per the stream spec (cleanse-before-throw convention from encryptor.cpp; entry id in every error):

- `rewrap_all_to_device`: skip pairs already in `entry_ids_wrapped_for(target.id)` (binary_search — resumable, no GPG op on skips); else unwrap K via `wrapped_key_for(id, my_fpr)` + `gpg_decrypt` (32-byte check), `gpg_encrypt_to_fingerprint(k, target.fingerprint)`, `insert_wrapped_key` (idempotent), `OPENSSL_cleanse` K on every path.
- `rotate_all`: refuse on zero active devices; `ensure_device_keys_local(active)`; legacy recipient = founding-if-active else lowest-id active (D5; `[INFO]` when the fallback triggers). Per entry: decrypt via the existing v1/v2-dispatching `Encryptor("").decrypt` (recipient unused on decrypt — proven by tests/test_compat.cpp:44), fresh `random_bytes(32)`, `serialize_v2(aes256_gcm_encrypt(...))`, wrap K′ to legacy + every active device, cleanse plaintext/K/K′, single `replace_entry_keys(id, blob, legacy_wrap, 2, wraps)` — crash between entries leaves every entry self-consistent. Not skip-resumable by design (re-rotation is harmless at 13–100 entries).
- `store_new_entry` / `replace_entry_password`: fresh K, v2 GCM, wrap to legacy recipient (→ `aes_key`, D5) and every active device, one txn via `insert_entry_with_keys`/`replace_entry_keys`. `active_devices().empty()` (unmigrated/empty DB) → byte-equivalent to today's single-wrap behavior with empty `wraps` (the repo's empty-wraps degradation path).

### 3.4 Read path (exact call sites)

`src/cli/screens.cpp:180` and `:193` (the only two `decrypt` consumers of `Entry.aes_key_armored` outside the gated compat test) become:

```cpp
std::string wrap = c_->repo->wrapped_key_for(e->id, c_->config->recipient_fingerprint())
                       .value_or(e->aes_key_armored);
std::string secret = c_->enc->decrypt(e->password_blob, wrap);
```

Pre-migration DBs and the 13 legacy rows keep decrypting via the unconditional `aes_key` fallback; `Entry.aes_key_armored` stays in the struct (compat test + fallback).

### 3.5 Write path (exact call sites)

`screens.cpp:70-72` (GenerateScreen save) → `sharing::store_new_entry(*c_->keys, c_->config->recipient_fingerprint(), password_, note)`; `screens.cpp:213-214` (EntryScreen edit) → `sharing::replace_entry_password(...)`. Status messages mention wrap count. `Encryptor` itself untouched. `screen.h` `AppContext` gains `sharing::KeyStore* keys` (forward-declared), owned by `main()` as `RepositoryKeyStore keys(*repo);`.

### 3.6 `src/cli/main.cpp` + `src/cli/commands.{h,cpp}` — argv dispatch

`int main(int argc, char** argv)`; `help/--help/-h` short-circuits before config/DB; otherwise bootstrap steps 1–4 exactly as today (shared `[FATAL]/[WARN]` behavior), then `if (!args.empty()) return cli::run_command(args, ctx);` else the unchanged menu loop.

Dispatch table (flags may follow the subcommand anywhere):

| argv                                           | flow                   | notes                                                                                                                                   |
| ---------------------------------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `migrate`                                      | `cmd_migrate`          | `apply_migrations()` + `apply_migrations_v2(founding-from-config)`, **hard-fail** (no WARN-and-continue), prints device/backfill counts |
| `entry add --note <s>`                         | `cmd_entry_add`        | password read from **stdin** (never argv); prints only the new integer id on stdout                                                     |
| `entry show <id>`                              | `cmd_entry_show`       | plaintext only on stdout; on failure **nothing on stdout**, error to stderr, exit 1                                                     |
| `device list [--porcelain]`                    | `cmd_device_list`      | human table, or `name<TAB>fingerprint<TAB>status` per line; warns when device tables absent                                             |
| `device add <name> <pubkey.asc> --fpr <40hex>` | `cmd_device_add`       | `--fpr` optional only on a TTY (prompted); exit 3 on mismatch                                                                           |
| `device revoke <name> [--rotate\|--no-rotate]` | `cmd_device_revoke`    | see consent rules below                                                                                                                 |
| `rewrap`                                       | `cmd_rewrap`           | resume/repair: `rewrap_all_to_device` per active device (existing pairs skip cheaply)                                                   |
| `rotate [--yes]`                               | `cmd_rotate`           | see consent rules below                                                                                                                 |
| else                                           | usage → stderr, exit 2 |                                                                                                                                         |

**`cmd_device_add`**: read pubkey file → resolve expected fpr (`--fpr`, else TTY prompt, else exit 2) → `db::normalize_fingerprint` → `gpg_import_public_key` (pre-inspected, §3.1) → compare (mismatch → exit 3, "NOT enrolling — key file may have been swapped"; nothing was imported thanks to pre-inspection) → idempotency dispatch on `list_devices()`:

- same name + same fingerprint + active → "already enrolled; resuming re-wrap";
- same name + different fingerprint → error, exit 1;
- **same name + status `revoked` → refuse: "name '<x>' was revoked; choose a new name — re-activating a revoked identity is not supported"** (fixed in review: this case previously fell through to `add_device` and surfaced as a raw pqxx UNIQUE violation);
- else `add_device(...)`.
  Then `rewrap_all_to_device(...)` with progress printing, summary, and the remote reminder: issue the device's onion auth key (`scripts/onion-auth-keygen.sh`), hand over onion address + `ca.crt` + socat unit — REMOTE.md §5.

**Rotation consent — one strength, every entry point** (fixed in review: revoke previously triggered a full all-rows rewrite behind a default-yes `[Y/n]` with no backup reminder, and silently auto-rotated in non-TTY — bypassing the gate `cmd_rotate` itself erects):

- `cmd_rotate`: always prints `[WARN] This rewrites every passwords row (new key + v2 GCM). Take a fresh backup first: ./scripts/backup.sh`. TTY → requires typed `ROTATE`. Non-TTY → requires `--yes`, else exit 2.
- `cmd_device_revoke`: look up by name (absent/already-revoked → exit 1); behavior by flag:
  - `--no-rotate`: `revoke_device(name)` (atomic status+wrap-delete), then loud `[WARN] Revocation INCOMPLETE: '<name>' may hold cached keys. Run 'pwmgr rotate' to finish.` (D4), exit 0.
  - `--rotate`: revoke, print the backup warning, then `cmd_rotate(ctx, /*assume_yes=*/true)` — the explicit flag is scripted consent of the same strength as `rotate --yes`. (This is what the Phase-5 harness calls.)
  - no flag, TTY: revoke, print the backup warning, then require typed `ROTATE` (identical to `cmd_rotate`); declined → the INCOMPLETE warning.
  - no flag, non-TTY: **exit 2 before doing anything** — "non-interactive revoke requires --rotate or --no-rotate".
  - Always print the full REMOTE.md §5 revoke checklist: delete the device's `.auth` file + `systemctl reload tor`, **and rotate the shared Postgres password (`scripts/rotate-db-password.sh --apply`) since every enrolled device knows it under D3** (fixed in review: the DB-password line was missing — a revoked-but-malicious device would have retained working DB credentials).

### 3.7 `DevicesScreen` (menu `[5] Devices`)

Thin veneer over the same `cmd_*` functions (D1: one implementation, both UIs): render via `list_devices()` in the ListScreen try/`status_err` style; footer `[a] add  [r] revoke  [w] rewrap (resume)  [b] back`; inputs prompt and call `cmd_device_add` / `cmd_device_revoke(..., no flag, TTY rules apply)` / `cmd_rewrap`, then `pause()`.

### 3.8 Crypto/CLI tests

`tests/gpg_test_home.h` — RAII `EphemeralKeyring`: `mkdtemp` 0700, set/restore `GNUPGHOME`, batch `%no-protection` ed25519/cv25519 keygen, `gpgconf --kill all` in dtor; restore is mandatory so a later `--gated` run still reaches the real keyring.

`tests/test_gpg_enroll.cpp` (ungated, no DB, no real secrets):

| Test | Asserts |
|---|---|
| import returns the imported fingerprint | export A from keyring1; import into fresh keyring2 == fprA; re-import == fprA; garbage throws; **a secret-key export is rejected with no keyring write** (pre-inspection) |
| swapped key file detected | A,B in one keyring; `gpg_import_public_key(exportA) != fprB` — the exact `cmd_device_add` comparison; `normalize_fingerprint` shape checks |
| enroll round-trip gives B real access | **(fixed in review: old seeding was self-contradictory — with B already active, `store_new_entry` wraps to B at creation and the engine would skip everything.)** Seed only A active; create 3 entries via `store_new_entry(store, fprA, ...)`; **then** add B active; `rewrap_all_to_device(store, B, fprA)` → `{total=3, wrapped=3, skipped=0}`; each entry decrypts via B's wrap (`Encryptor("").decrypt(blob, store.wrapped_key_for(id, fprB)) == pt_i`) |
| enroll is resumable | second run → `{wrapped=0, skipped=3}`, row counts unchanged |
| rotate: revoked device loses access; v1 upgrades | entry1 = fabricated v1 blob (local `cbc_encrypt_b64` helper as in test_aes.cpp), entry2 = v2; both wrapped to B; mark B revoked in the fake; `rotate_all` → `{rotated=2, upgraded_v1=1}`; all blobs `"v2:"`-prefixed; A decrypts; B has no wraps; **the wrong-key check first runs `parse_password_blob` on the stored blob, asserts `version==V2_Gcm`, then `CHECK_THROWS(aes256_gcm_decrypt(parsed.payload, old_k))`** (fixed in review: feeding the raw `"v2:"`-prefixed blob to the decryptor throws on base64 alone, masking a wrong-key regression); legacy `aes_key` refreshed and decrypts for A (D5) |
| write path wraps to all active + legacy | 2 active devices → legacy aes_key + 2 wraps; fallback for unknown fpr |

`tests/fake_keystore.h`: `InMemoryKeyStore` over std::maps, atomic map mutations for the one-txn methods, raw state exposed.

`tests/test_repository.cpp` gated additions: `entry+keys insert/replace atomic and queryable` (two devices, wraps queryable per device, legacy fallback after wrap delete, `replace_entry_keys` swap, `founding_device()` = lowest id) and `device-table methods degrade safely when tables absent` (per the §2.3 contract — including the throw cases).

---

## §4 Work-stream: Network scripts (Phases 3+4 tooling)

Scope: scripts + templates + docs + script-tests only. Committed inert; run later by the user. Conventions: `set -euo pipefail`, `[*]/[OK]/[!!]` prefixes, `PWMGR_*` env overrides, `umask 077` before secrets, typed-confirmation gates for destructive actions, long header comment per script. The no-surprise rule: a script performs a step only if it needs neither root nor systemctl (or the path was explicitly overridden); everything else is printed as copy-pasteable instructions.

Doc anchors corrected (fixed in review): gen-db-certs implements MULTI_DEVICE_PLAN.md **:283-285** (Phase 3 step 2); onion-auth-keygen's deliverable bullet is **:306-307**.

### 4.1 `scripts/gen-db-certs.sh`

As specified in the stream spec (kept intact — no reviewer issues): positional `<lan-ip-or-hostname> [extra-san…]`; outputs `ca.key`/`server.key` 0600 + `ca.crt`/`server.crt` 0644 into `$PWMGR_CERT_DIR` (default `~/.config/pwmgr/db-certs`); RSA-3072, `PWMGR_CA_DAYS`/`PWMGR_SRV_DAYS` overrides; SAN list auto-typed IP:/DNS:; complete set → no-op exit 0, partial set → refuse exit 1; `-extfile` signing, `openssl verify` self-check; prints the seven root-needed follow-ups (PGDATA install, postgresql.conf, pg_hba `hostssl pwmgr pwmgr <subnet> scram-sha-256`, reload, firewall, distribute `ca.crt`, **rotate the DB password first**) and the move-`ca.key`-offline warning.

### 4.2 `scripts/onion-auth-keygen.sh`

Per the stream spec (REMOTE.md §3.2 recipe verbatim: x25519 via openssl, raw key = last 32 bytes of DER, unpadded base32 via python3; shred-on-exit temps), with two arg-parsing fixes (fixed in review):

- `--onion`/`--write-dir` use `"${2:?--onion needs a value}"`-style expansion (no unbound-variable abort when the flag is last);
- device-name regex rejects a leading dash: `^[A-Za-z0-9._][A-Za-z0-9._-]*$` (so an omitted name can't silently consume `--onion` as the device).
  Prints the server `.auth` line and client `.auth_private` line; `--write-dir` writes both 0600 with the move-then-shred warning; prints install steps (tor reload, ClientOnionAuthDir, unit render) — never touches `/var/lib/tor` or systemctl itself.

### 4.3 `scripts/setup-onion.sh`

Marker-guarded idempotent torrc block + `HiddenServiceDir`/`authorized_clients` 0700; chown only when root and the `$PWMGR_TOR_USER` exists; `systemctl enable --now tor` only with explicit `--enable`; prints the onion address if `hostname` exists; ends with the `hs_ed25519_secret_key` offline-backup reminder. Writability gate **rewritten as functions with explicit grouping and a nonexistent-torrc path** (fixed in review: the old `A || B && C` chain parsed as `(A||B)&&C`, proceeding when torrc was unwritable and refusing on a fresh sandbox where torrc didn't exist yet):

```bash
torrc_writable() {
  if [ -e "$TORRC" ]; then [ -w "$TORRC" ];
  else [ -w "$(dirname "$TORRC")" ]; fi          # creatable counts as writable
}
hsdir_writable() { [ -w "$HS_DIR" ] || [ -w "$(dirname "$HS_DIR")" ]; }
if ! torrc_writable || ! hsdir_writable; then manual_instructions; exit 1; fi
[ -e "$TORRC" ] || : > "$TORRC"
```

### 4.4 `scripts/templates/pwmgr-onion-forward.service`

systemd **user** unit template, placeholders `@ONION_ADDR@`/`@LOCAL_PORT@`/`@SOCKS_PORT@`, socat `TCP-LISTEN:@LOCAL_PORT@,bind=127.0.0.1,reuseaddr,fork SOCKS4A:127.0.0.1:@ONION_ADDR@.onion:5432,socksport=@SOCKS_PORT@`, `Restart=on-failure`, `NoNewPrivileges`, `PrivateTmp`. Header documents the sed render + the system-tor dependency gap. **(fixed in review: `Description` now uses `@LOCAL_PORT@` — `%I` expands to nothing in a non-instantiated unit — and the hardcoded `Documentation=file:///home/user/...` line is dropped; the unit runs on other devices.)**

### 4.5 `scripts/rotate-db-password.sh`

Dry-run by default; `--apply` requires typing the DB name. Flow on `--apply`, with two review fixes folded in:

1. Fresh backup via `scripts/backup.sh` (abort on failure — backup-before-prod-write invariant).
2. Generate 32-char alnum password (never printed, never in argv).
3. **(fixed in review: lockout window)** Persist the complete new pgpass line to `"$PGPASS.pending"` (umask 077, 0600) **before** ALTER ROLE; an EXIT/ERR trap prints its path on any abort; the file is removed only after step 6 verifies. A crash between ALTER and the pgpass write is now recoverable without the postgres superuser.
4. `ALTER ROLE ${PGUSER} WITH PASSWORD '<new>'` via psql stdin heredoc, `ON_ERROR_STOP`.
5. Update `~/.pgpass` (dedupe the matching line, append new, 0600, `.bak` kept) and atomically strip `password=...` from `db_connection` in `$PWMGR_CONFIG` via the python3 helper (`.bak` 0600).
6. Verify `SELECT 1` with `env -u PGPASSWORD PGPASSFILE="$PGPASS"`. Then remove `.pending`.

**Old-password prerequisite (fixed in review: undocumented):** header + dry-run output state "the backup and ALTER steps authenticate with the _current_ password — requires `PGPASSWORD`, an existing `~/.pgpass` entry, or a TTY for prompts". Convenience: if `PGPASSWORD` is unset and `$CFG`'s `db_connection` carries a `password=` token, export it as `PGPASSWORD` for the backup+ALTER steps only.

**Final warning reworded (fixed in review: factually off):** the repo-root `config.json` points at `host=192.168.100.138 dbname=mydb user=dbuser` — a stale, historical connection that this rotation does **not** affect. The script now prints a hygiene note ("repo-root config.json still embeds a historical `password=` token; clean it up") instead of the wrong "old binary will stop connecting / ~/.pgpass fallback" claim.

### 4.6 `scripts/export-key.sh` (comment-only)

Add a paragraph to the header guide: the onion identity key `/var/lib/tor/pwmgr/hs_ed25519_secret_key` **is** the address — back up the whole `HiddenServiceDir` to the same offline media as the GPG secret key (REMOTE.md §3.3). **(fixed in review: this REMOTE.md deliverable was previously owned by no stream.)**

### 4.7 `tests/scripts/test_network_scripts.sh` + Makefile `test-scripts`

Self-contained sandbox harness (bash/coreutils/openssl/python3 only; PATH stubs for psql/pg_dump/systemctl that log argv+stdin). Two harness blockers fixed (fixed in review — both reproduced on this machine):

- **`t()` no longer runs the subshell inside the `if` condition** (where bash ignores `set -e`, making every multi-step test false-green): `out=$( set -e; "$2" 2>&1 ); rc=$?; if [ "$rc" -eq 0 ]; then ...`.
- **`sandbox()` no longer self-destructs**: it appends `$SB` to a global `SANDBOXES` array cleaned by a single harness-level `trap ... EXIT` (the old per-function `RETURN` trap fired when `sandbox()` itself returned, deleting the dir before the test body ran).

Test list as in the stream spec (25 tests across the four scripts: cert set/SAN/perms/no-op/partial-refusal; keygen line formats/uniqueness/no-residue/0600/arg validation; setup-onion append-once/0700/systemctl gating/unwritable-instructions/hostname; rotate dry-run/wrong-confirm/backup-before-ALTER/no-password-leak/pgpass/config-strip), with these setup corrections (fixed in review):

- setup-onion tests **pre-create `$SB/torrc`** (and one new test covers the nonexistent-torrc-but-writable-parent path succeeding, plus one for torrc-unwritable → manual instructions, exit 1);
- rotate tests export `PWMGR_BACKUP_DIR=$SB/backups` **and `HOME=$SB`** so the real `backup.sh` never writes the real home;
- `onion_keygen_no_temp_residue` does `mkdir -p "$SB/tmp"` before running with `TMPDIR=$SB/tmp`;
- new `rotate_apply_leaves_no_pending_on_success` / `rotate_pending_survives_alter_failure` tests for the §4.5 recovery file.

Makefile: `test-scripts:` target + `.PHONY` update; `make test` itself unchanged (stays `--no-gated` C++-only).

### 4.8 Doc edits

`docs/REMOTE.md`: three surgical edits replacing "Phase 4 deliverable" forward-references with the committed script paths/render command, + one line in §3.1 pointing at `setup-onion.sh`. `docs/ROTATION.md`: insert the "Automated:" paragraph; retitle the section "(mandatory before any network tier)".

---

## §5 Work-stream: Test harness (Phase 5 rehearsals)

### 5.1 `docker/compose.test.yml`

As in the stream spec (`name: pwmgr-test`; `db` = postgres:18 with `pwmgr_test`, **no host ports**, schema.sql via initdb.d; `deviceA`/`deviceB` share one image built from the existing Dockerfile, entrypoint bind-mounted, shared volume for pubkey exchange), with two fixes (fixed in review):

- tmpfs mounted at **`/var/lib/postgresql`** (the postgres:18 image's PGDATA lives under `/var/lib/postgresql/18/docker`; the old `/var/lib/postgresql/data` mount silently covered nothing);
- healthcheck `pg_isready **-h 127.0.0.1** -U pwmgr -d pwmgr_test` (the temp init-phase server is socket-only; TCP readiness implies the final server, removing the race against step 0's `pwmgr migrate`).

### 5.2 `docker/device-entrypoint.sh`

Per the stream spec (ephemeral `%no-protection` ed25519/cv25519 key, idempotent across restarts; export pubkey+fpr to `/shared`; write `/config/config.json` satisfying config.cpp validation; ready-sentinel; `sleep infinity`), plus **(fixed in review: bare `pwmgr` was never on PATH — every harness step would die "command not found")**:

```bash
ln -sf /app/build/make/pwmgr /usr/local/bin/pwmgr
```

### 5.3 `scripts/test-two-devices.sh`

Five-assertion orchestrator, exit codes 11–15/20, `PWMGR_KEEP=1` keeps the stack up. Changes vs. the stream draft:

- `dexec` uses `bash -c` (not `-lc` — a login shell's profile output would pollute captured ids/plaintexts) (fixed in review).
- CLI calls renamed to the reconciled surface: `device add deviceB /shared/deviceB.pub.asc --fpr "$FPR_B"`, `device list --porcelain`, `device revoke deviceB --rotate`.
- **Step 1 seeds 3 entries** (distinct secrets/notes) and steps 2–5 assert all of them — re-wrap completeness `NKB == NPW == 3+`, rotation changes every blob to `v2:`, B fails on each, A round-trips each (fixed in review: a single entry degenerated the per-entry-loop assertions to 1/1). Only v2-created entries are covered here; the v1-upgrade path is proven by the ungated rotate test (§3.8) and the staging rehearsal.
- Step 0: only deviceA runs `pwmgr migrate` (founding = A); step 2's negative control (`devices` count == 1, B cannot decrypt pre-enroll) now holds structurally because v2 never auto-runs at startup (§2.6) **and** the founding insert is empty-table-guarded (§2.4).

### 5.4 `scripts/staging-rehearsal.sh`

Native host script, writes only `pwmgr_test`; exit codes 30–35. Flow: restore latest `~/pwmgr-backups/pwmgr_*.dump` via `PWMGR_RESTORE_DB=pwmgr_test scripts/restore.sh` → snapshot (`psql --csv` six-column snapshot **and** `pg_dump --data-only --table=passwords` byte-compare) → `PWMGR_CONFIG=$WORK/config.json build/make/pwmgr migrate` → re-snapshot, `cmp` both (exit 32 on drift) → backfill shape (exactly 1 device, founding fingerprint, one `password_keys` row per entry, each `wrapped_key = aes_key` byte-equal; exit 33) → second `migrate`, nothing changes (exit 34). Review fixes folded in:

- **The `pwmgr_tests --gated` invocation is dropped entirely** (fixed in review: the framework has no per-test filter, so `--gated` unavoidably runs the repository CRUD test, which either fails on unset `PWMGR_TEST_DB` or — pointed at the staging DB — `DROP TABLE passwords` wipes/errors the just-restored copy). The gated phase (`PWMGR_STAGING_DECRYPT=1`, exit 35) is now only the all-rows loop: `pwmgr entry show "$id"` for every id — which end-to-end exercises the compat row (id 1) against restored real data, the plan's actual requirement.
- Source config resolved exactly like the binary: `CFG="${PWMGR_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/pwmgr/config.json}"` (fixed in review: the hardcoded path could pick a non-authoritative config — the project memory tracks which one is real).
- The python dbname swap asserts a word-boundary match first (`re.search(r'\bdbname=pwmgr\b', ...)` → `re.sub` with the same boundary) and asserts the founding fingerprint `29974BE0…C21A600C` appears in the loaded config before proceeding (fixed in review: substring replace could mangle `dbname=pwmgr2`; the step-5 device check could fail for an unrelated reason).

### 5.5 `scripts/restore.sh` (modified)

At the `TDB="pwmgr_restore_test"` line (restore.sh:17): `TDB="${PWMGR_RESTORE_DB:-pwmgr_restore_test}"` + guard (refuse `pwmgr`, require `*test*`). PRODUCTION path untouched.

### 5.6 `docker/compose.net.yml` + `scripts/test-net-negative.sh`

Tier-1 negatives (REMOTE.md §2 acceptance): plaintext refused (41), wrong CA refused under verify-full (42), wrong password refused (43), psql verify-full positive control (44). Review fixes folded in:

- Generated `pg_hba.conf` **appends `local all all trust`** (fixed in review: with only `hostssl` lines, the postgres image's init-phase unix-socket connections are rejected and the container never becomes healthy; `local` lines don't affect the TCP-facing assertions). Comment reworded: "same _mechanism_ REMOTE.md §2.4 prescribes (hostssl + scram, no trust over TCP); scope intentionally widened for the throwaway rig" (fixed in review: it is not "the exact policy" — REMOTE.md scopes by db/user/subnet).
- `server.key` ownership fixed with a privileged one-shot **before `up`**: `docker run --rm -v "$PWMGR_NET_DIR/server":/c alpine sh -c 'chown 999:999 /c/server.key && chmod 600 /c/server.key'` (verify uid 999 against the image at implementation time) (fixed in review: a host-uid-owned key aborts `ssl=on` startup; the old script shipped a `chmod 0640` + a question-mark comment).
- Cert generation uses the real Stream-C contract: `PWMGR_CERT_DIR="$PWMGR_NET_DIR/server" "$HERE/scripts/gen-db-certs.sh" db-tls` (cross-stream fix: the draft invented `--out/--host` flags).
- New optional **test 45** (fixed in review: plan §5 item 5 says the positive control should be the _pwmgr client path_, not bare psql): if the `pwmgr-test:local` image exists, run it with a generated config `host=db-tls … sslmode=verify-full sslrootcert=/certs/ca.crt` against `pwmgr_net_test` and assert `pwmgr migrate` exits 0 (throwaway DB; name contains "test"). Skipped with a notice when the image is absent.
- Ends by printing the manual-only checklist: onion positive / no-`.auth_private` negative / `.auth`-deletion revocation / physical-LAN e2e (ground rules forbid enabling tor; a real hidden service for a test DB is slow/flaky/pointless to automate).

### 5.7 Makefile + docs

Targets `test-devices`, `test-staging`, `test-net` (phony; `test-devices` builds inside the image — host libpqxx version irrelevant; `test-staging` requires a prior host `make`). `docs/MULTI_DEVICE_PLAN.md` §5 items 3–5 get "(→ `make test-devices` / `make test-staging` / `make test-net`; onion checks manual)" pointers.

---

## §6 Commit/PR sequence

Ordered; data layer → crypto/CLI → harness; network scripts independent (may interleave anywhere after 1). **Every commit: `make && make test` green. Invariant check "13 v1 rows still decryptable" = the gated compat test plus, where marked, the explicit verification step.** No commit writes prod: migration v2 is opt-in only (§2.6), so even running the daily binary against `host=localhost dbname=pwmgr` after any of these commits performs no v2 write. The first real v2 run is Phase 6, preceded by `./scripts/backup.sh`.

| #   | Commit                                                                                                                          | Verification                                                                                                        | 13-row invariant                                                                                              |
| --- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| 1   | `db: Device/FoundingDevice/WrappedKey structs + fingerprint validation`                                                         | `make test` (test_device.cpp)                                                                                       | untouched (pure addition)                                                                                     |
| 2   | `config: optional device_name key with username fallback`                                                                       | `make test` (test_config.cpp)                                                                                       | untouched                                                                                                     |
| 3   | `db: migration v2 as opt-in apply_migrations_v2 (devices, password_keys, guarded founding backfill) + has_device_tables_ probe` | gated: probe-false + idempotency tests on `pwmgr_test`; snapshot proves `passwords` bit-identical pre/post two runs | **explicitly asserted** by the gated snapshot test; prod untouchable (v2 opt-in)                              |
| 4   | `db: device repository API (list/add/revoke, wrapped_key_for fallback, wrap inserts, atomic entry+keys ops)`                    | gated: remaining test_repository_devices.cpp + test_repository.cpp additions                                        | fallback path covered by degradation test; dead code from the CLI's view                                      |
| 5   | `crypto: gpg public-key import/export with pre-import inspection + ephemeral-keyring fixture`                                   | `make test` (import/export/swapped-key tests, throwaway keyring)                                                    | untouched                                                                                                     |
| 6   | `sharing: rewrap/rotate engines + KeyStore seam + InMemoryKeyStore`                                                             | `make test` (enroll round-trip, resume, rotate, write-path — full lifecycle proven with throwaway keys, no DB)      | untouched                                                                                                     |
| 7   | `cli: read path resolves wraps via wrapped_key_for (aes_key fallback)`                                                          | `make test`; gated compat test still green; manual smoke: decrypt one entry against a test DB                       | **explicitly re-verified** (gated compat + fallback); smallest blast radius, easiest revert                   |
| 8   | `cli: write path wraps new entries to all active devices (keeps legacy aes_key, D5) + AppContext keystore`                      | `make test`; against an unmigrated DB writes are byte-equivalent to today                                           | untouched (reads unchanged)                                                                                   |
| 9   | `cli: argv dispatch (migrate, entry add/show, device subcommands, rewrap, rotate) + Devices menu screen`                        | `make test`; `pwmgr help`; gated: `migrate` + lifecycle smoke on `pwmgr_test`                                       | untouched until user runs `migrate` (Phase 6, backup first)                                                   |
| 10  | `scripts: network-tooling test harness + gen-db-certs.sh`                                                                       | `make test-scripts` (cert tests)                                                                                    | untouched (no DB contact)                                                                                     |
| 11  | `scripts: rotate-db-password.sh (+ pending-file recovery) + ROTATION.md`                                                        | `make test-scripts` (rotate tests, stubs only)                                                                      | untouched (inert until `--apply`, which forces a backup first)                                                |
| 12  | `scripts: onion-auth-keygen.sh + client socat unit template + REMOTE.md §3.2/§3.4`                                              | `make test-scripts` (keygen/template tests)                                                                         | untouched                                                                                                     |
| 13  | `scripts: setup-onion.sh + REMOTE.md §3.1 + export-key.sh onion-backup note`                                                    | `make test-scripts` (setup-onion tests)                                                                             | untouched                                                                                                     |
| 14  | `test: docker two-device rig (compose + device entrypoint + pwmgr symlink)`                                                     | `docker compose -f docker/compose.test.yml up -d --build` → two ready sentinels                                     | untouched (no host ports, `pwmgr_test` only)                                                                  |
| 15  | `test: two-device lifecycle orchestrator (make test-devices)` — requires #9                                                     | `make test-devices` → all five assertions, 3 seeded entries                                                         | untouched (containers only)                                                                                   |
| 16  | `test: staging rehearsal (make test-staging) + restore.sh PWMGR_RESTORE_DB override` — requires #9                              | `make test-staging` (+`PWMGR_STAGING_DECRYPT=1` once)                                                               | **explicitly asserted**: bit-identical `passwords` on a restored copy of the real 13 rows; prod never touched |
| 17  | `test: Tier-1 TLS negative rig (make test-net) + manual onion checklist` — requires #10                                         | `make test-net` → 41–45                                                                                             | untouched (throwaway `pwmgr_net_test`)                                                                        |
| 18  | `docs: MULTI_DEVICE_PLAN §5 make-target pointers`                                                                               | doc-only                                                                                                            | untouched                                                                                                     |

Dependency notes (fixed in review: the crypto stream understated this): commits 5–6 can land before/parallel to the data layer only if `db/device.h` (commit 1) exists; commits 7–9 are hard-blocked on commits 3–4 (`wrapped_key_for`, `has_device_tables_`, `list_devices`, `add_device`, `revoke_device`). Commits 10–13 are independent of everything (interleave freely); 14 anytime; 15–16 after 9; 17 after 10.

---

## §7 Definition of done per phase + what stays manual

| Phase          | Done when                                                                                                                                                                                                                                   | Deliberately manual (execution time, per no-install rule)                                                                                                                                                                                                                                        |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1 — data layer | Commits 1–4 merged; `make test` green; gated suite green on `pwmgr_test`; bit-identity snapshot test passing twice in a row                                                                                                                 | —                                                                                                                                                                                                                                                                                                |
| 2 — crypto+CLI | Commits 5–9 merged; full enroll/rotate lifecycle green under plain `make test` (ephemeral keyrings); gated compat still green; `pwmgr help` documents the full surface                                                                      | —                                                                                                                                                                                                                                                                                                |
| 3 — LAN        | Commits 10–11 merged; `make test-scripts` green                                                                                                                                                                                             | **User runs**: `rotate-db-password.sh --apply` (DB password rotation — recommended before anything listens; the real password was never committed), `gen-db-certs.sh <LAN-IP>`, then the printed root steps: PGDATA cert install, postgresql.conf, pg_hba, reload, firewall, distribute `ca.crt` |
| 4 — onion      | Commits 12–13 merged; `make test-scripts` green                                                                                                                                                                                             | **User runs**: `setup-onion.sh` (sudo) and — explicitly, later — `setup-onion.sh --enable` (tor enablement); per-device: install `tor`+`socat`, install `.auth_private`, render+enable the user unit; offline-backup the `HiddenServiceDir`                                                      |
| 5 — rehearsals | Commits 14–18 merged; `make test-devices` 5/5; `make test-staging` clean (and once with `PWMGR_STAGING_DECRYPT=1`); `make test-net` 41–45                                                                                                   | Onion positive/negative/revocation + physical-LAN e2e (printed checklist — tor must not be enabled by automation)                                                                                                                                                                                |
| 6 — production | `./scripts/backup.sh` → `pwmgr migrate` on the real DB → list + decrypt one entry → enroll the real second device (`device add` after out-of-band fingerprint verification) → second device decrypts over LAN → only then onion credentials | Everything in this row is user-driven; rollback at any step = `DROP TABLE password_keys, devices;` and/or restore the dump (`passwords` is never modified by enrollment)                                                                                                                         |

Also deferred to the user at execution time: package installs on client devices (build deps, tor, socat), the DB password rotation itself, tor enablement, and any `pacman` work — no commit in this plan installs or enables anything.

---

## §8 Decisions (resolved 2026-06-11 — defaults confirmed)

1. **Revoking the founding device while D5 is active: ALLOWED, with a loud `[INFO]` during rotate.** Rotate writes `passwords.aes_key` wrapped to the lowest-id remaining active device, so old binaries _on the founding device_ can no longer read post-rotation rows — which is exactly what revocation is for. Refusing would block the one scenario where revocation matters most (the founding device is lost/compromised).
2. **Re-enrolling a revoked device name is REFUSED** ("choose a new name", e.g. `arch-laptop-2`). No `device reactivate` path: the `devices` table stays an append-only audit trail, and a revoked row never silently becomes trusted again. A genuinely returning device re-enrolls with a fresh GPG key anyway (its old key must be considered burned).
3. **`make test` stays byte-identical**; script/docker/staging/network tests live behind separate `make test-scripts` / `test-devices` / `test-staging` / `test-net` targets. The plain unit gate stays fast and dependency-free (no docker, no DB); the heavier targets are run when their phase is in play.
