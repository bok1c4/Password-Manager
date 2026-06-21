#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <pqxx/pqxx>

#include "db/device.h"

namespace pwmgr::db {

struct NoteRow {
  std::int64_t id;
  std::string note;
  int enc_version;
};

struct Entry {
  std::int64_t id;
  std::string password_blob;    // passwords.password (v1 bare / v2 "v2:"-prefixed)
  std::string note;
  std::string aes_key_armored;  // convert_from(aes_key,'UTF8')
  int enc_version;
};

// One cell of the access matrix: device_id can decrypt password_id. Mirrors a
// password_keys row without the wrapped bytes — the CMS only needs the shape.
struct WrapPair {
  std::int64_t password_id;
  std::int64_t device_id;
};

// Owns one long-lived libpqxx connection (RAII). All queries are parameterized.
// The bigint primary key is read as int64. Reads keep convert_from(aes_key,
// 'UTF8') for byte-compatibility with the existing armored-ASCII rows.
class Repository {
 public:
  explicit Repository(const std::string& conn_str);

  bool test_connection();
  void apply_migrations();  // additive, idempotent (adds enc_version)

  // Migration v2 (additive, idempotent, ONE transaction): creates the
  // devices + password_keys tables, registers `founding` ONLY IF the devices
  // table is empty (an enrolled device's `migrate` must never self-enroll),
  // and backfills password_keys from passwords.aes_key (copies, never moves;
  // only ever targeted at the founding = lowest-id device, since aes_key is
  // by definition the founding wrap). NEVER called from normal startup —
  // only via `pwmgr migrate` or PWMGR_MIGRATE_V2=1.
  void apply_migrations_v2(const FoundingDevice& founding);

  // ---- multi-device API. Degradation contract on a pre-migration DB
  // (has_device_tables_ == false), method by method:
  //   list_devices() / active_devices()        -> {}
  //   founding_device()                        -> nullopt
  //   entry_ids_wrapped_for()                  -> {}
  //   wrapped_key_for()        -> falls back to passwords.aes_key
  //   revoke_device()                          -> false
  //   add_device() / insert_wrapped_key()      -> throw std::runtime_error
  //                                               ("device tables not migrated")
  //   replace_entry_keys() / insert_entry_with_keys() with EMPTY wraps
  //                            -> legacy-equivalent SQL; with non-empty wraps
  //                               -> throw (never silently drop the matrix)
  bool has_device_tables() const { return has_device_tables_; }
  std::vector<Device> list_devices();    // ORDER BY id
  std::vector<Device> active_devices();  // status='active' ORDER BY id
  std::optional<Device> founding_device();  // lowest devices.id
  // Validates the fingerprint (std::invalid_argument on a malformed one);
  // returns the new device id.
  std::int64_t add_device(const Device& d);
  // status='revoked' + revoked_at + DELETE its password_keys rows, one txn.
  // false if there is no ACTIVE device of that name.
  bool revoke_device(std::string_view name);
  // The per-device wrap for (entry, fingerprint) when the device is active;
  // otherwise the unconditional legacy fallback passwords.aes_key (this keeps
  // the 13 v1 rows readable on any DB state; the fallback returns the founding
  // wrap even for unknown fingerprints — undecryptable for them by design,
  // access control lives in the join). nullopt only if the entry is gone.
  std::optional<std::string> wrapped_key_for(std::int64_t password_id,
                                             std::string_view fingerprint);
  void insert_wrapped_key(std::int64_t password_id, std::int64_t device_id,
                          std::string_view wrapped_armored);  // idempotent
  std::vector<std::int64_t> all_entry_ids();  // passwords.id ASC
  // Sorted (the enroll engine binary-searches it).
  std::vector<std::int64_t> entry_ids_wrapped_for(std::int64_t device_id);
  // The WHOLE access matrix in one query: every (password_id, device_id) in
  // password_keys, ascending by (password_id, device_id). The CMS pivots it
  // both ways (per-entry devices, per-device counts). Empty pre-migration.
  std::vector<WrapPair> wrap_pairs();
  // Rotate support, one txn: update blob + legacy wrap (+enc_version when the
  // column exists; throws if the id matched no row), then replace this entry's
  // password_keys rows with exactly `wraps` (plain INSERTs — a duplicate
  // device_id in `wraps` is a caller bug and must abort loudly).
  void replace_entry_keys(std::int64_t id, std::string_view password_blob,
                          std::string_view founding_wrap_armored,
                          int enc_version, const std::vector<WrappedKey>& wraps);
  // Write-path support, one txn: insert the entry plus its wraps.
  std::int64_t insert_entry_with_keys(std::string_view password_blob,
                                      std::string_view founding_wrap_armored,
                                      std::string_view note, int enc_version,
                                      const std::vector<WrappedKey>& wraps);

  std::vector<NoteRow> list_notes();
  std::vector<NoteRow> search_notes(std::string_view term);
  std::optional<Entry> get_entry(std::int64_t id);

  std::int64_t insert_entry(std::string_view password_blob,
                            std::string_view aes_key_armored,
                            std::string_view note, int enc_version);
  void update_password(std::int64_t id, std::string_view password_blob,
                       std::string_view aes_key_armored, int enc_version);
  void update_note(std::int64_t id, std::string_view note);
  bool delete_entry(std::int64_t id);

  std::optional<std::string> find_user_by_key_or_username(
      std::string_view pubkey, std::string_view username);
  void save_public_key_ref(std::string_view pubkey, std::string_view fingerprint,
                           std::string_view username);

 private:
  bool detect_enc_version();    // probes information_schema once
  bool detect_device_tables();  // probes information_schema once (both tables)

  pqxx::connection conn_;
  // Whether the passwords.enc_version column exists. Reads/writes are decoupled
  // from the migration: if it never ran (e.g. no ALTER privilege), legacy v1
  // rows stay readable and the "v2:" blob prefix still disambiguates versions.
  bool has_enc_version_ = false;
  // Whether devices + password_keys exist (migration v2). Same decoupling: the
  // binary runs fine against an unmigrated DB (see the per-method degradation
  // contract on the multi-device API).
  bool has_device_tables_ = false;
};

// Pure pivots over a wrap_pairs() result — no DB, so the CMS aggregation is
// unit-testable on its own. Both de-duplicate and return ascending ids.
//   wraps_by_entry:  password_id -> device_ids that can decrypt it
//   count_by_device: device_id   -> number of distinct entries it can decrypt
std::map<std::int64_t, std::vector<std::int64_t>> wraps_by_entry(
    const std::vector<WrapPair>& pairs);
std::map<std::int64_t, std::int64_t> count_by_device(
    const std::vector<WrapPair>& pairs);

}  // namespace pwmgr::db
