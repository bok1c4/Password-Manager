#pragma once
#include <cstdint>
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

  bool has_device_tables() const { return has_device_tables_; }

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

}  // namespace pwmgr::db
