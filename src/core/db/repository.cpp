#include "db/repository.h"

namespace pwmgr::db {

Repository::Repository(const std::string& conn_str) : conn_(conn_str) {
  has_enc_version_ = detect_enc_version();
  has_device_tables_ = detect_device_tables();
}

bool Repository::detect_enc_version() {
  try {
    pqxx::work txn(conn_);
    pqxx::result r = txn.exec(
        "SELECT 1 FROM information_schema.columns WHERE table_name='passwords' "
        "AND column_name='enc_version' LIMIT 1");
    txn.commit();
    return !r.empty();
  } catch (...) {
    return false;
  }
}

bool Repository::detect_device_tables() {
  try {
    pqxx::work txn(conn_);
    // Both tables must exist; scoped to the current schema so a stray table
    // elsewhere cannot double-count.
    pqxx::result r = txn.exec(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = current_schema() "
        "AND table_name IN ('devices','password_keys') HAVING count(*) = 2");
    txn.commit();
    return !r.empty();
  } catch (...) {
    return false;
  }
}

bool Repository::test_connection() {
  try {
    return conn_.is_open();
  } catch (...) {
    return false;
  }
}

void Repository::apply_migrations() {
  pqxx::work txn(conn_);
  // Bound so a stuck ALTER aborts instead of holding ACCESS EXCLUSIVE.
  txn.exec("SET LOCAL lock_timeout = '5s'");
  txn.exec("SET LOCAL statement_timeout = '30s'");
  // Additive + idempotent: existing rows default to v1 with no data rewrite.
  txn.exec(
      "ALTER TABLE passwords ADD COLUMN IF NOT EXISTS enc_version smallint NOT "
      "NULL DEFAULT 1");
  txn.exec(
      "CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, "
      "applied_at timestamptz NOT NULL DEFAULT now())");
  txn.exec("INSERT INTO schema_migrations(version) VALUES (1) ON CONFLICT DO NOTHING");
  txn.commit();
  has_enc_version_ = true;
}

void Repository::apply_migrations_v2(const FoundingDevice& founding) {
  const std::string fpr = normalize_fingerprint(founding.fingerprint);
  pqxx::work txn(conn_);
  txn.exec("SET LOCAL lock_timeout = '5s'");
  txn.exec("SET LOCAL statement_timeout = '30s'");
  txn.exec(
      "CREATE TABLE IF NOT EXISTS devices ("
      "  id           bigserial PRIMARY KEY,"
      "  name         text   UNIQUE NOT NULL,"
      "  fingerprint  char(40) UNIQUE NOT NULL,"
      "  public_key   text   NOT NULL,"
      "  status       text   NOT NULL DEFAULT 'active',"
      "  enrolled_at  timestamptz NOT NULL DEFAULT now(),"
      "  revoked_at   timestamptz)");
  txn.exec(
      "CREATE TABLE IF NOT EXISTS password_keys ("
      "  password_id  bigint NOT NULL REFERENCES passwords(id) ON DELETE CASCADE,"
      "  device_id    bigint NOT NULL REFERENCES devices(id),"
      "  wrapped_key  bytea  NOT NULL,"
      "  created_at   timestamptz NOT NULL DEFAULT now(),"
      "  PRIMARY KEY (password_id, device_id))");
  // An invalid/empty fingerprint skips registration + backfill; the tables are
  // still created so the probe flips and the device API becomes usable.
  if (!fpr.empty()) {
    // Register the founding device ONLY on an empty table: an enrolled second
    // device running `migrate` must never self-enroll as founding.
    txn.exec(
        "INSERT INTO devices (name, fingerprint, public_key) "
        "SELECT $1, $2, $3 WHERE NOT EXISTS (SELECT 1 FROM devices) "
        "ON CONFLICT (fingerprint) DO NOTHING",
        pqxx::params{founding.name, fpr, founding.public_key_armored});
    // Backfill: COPY the legacy wrap into the access matrix. aes_key is by
    // definition wrapped to the FOUNDING key, so the copy only ever targets
    // the lowest-id device — a later device re-running `migrate` with its own
    // fingerprint must not be credited with wraps it cannot decrypt.
    txn.exec(
        "INSERT INTO password_keys (password_id, device_id, wrapped_key) "
        "SELECT p.id, d.id, p.aes_key FROM passwords p CROSS JOIN devices d "
        "WHERE d.fingerprint = $1 AND d.id = (SELECT min(id) FROM devices) "
        "ON CONFLICT (password_id, device_id) DO NOTHING",
        pqxx::params{fpr});
  }
  txn.exec(
      "INSERT INTO schema_migrations(version) VALUES (2) ON CONFLICT DO "
      "NOTHING");
  txn.commit();
  has_device_tables_ = true;
}

std::vector<NoteRow> Repository::list_notes() {
  pqxx::work txn(conn_);
  pqxx::result r =
      has_enc_version_
          ? txn.exec("SELECT id, note, enc_version FROM passwords ORDER BY id ASC")
          : txn.exec("SELECT id, note FROM passwords ORDER BY id ASC");
  txn.commit();
  std::vector<NoteRow> out;
  out.reserve(r.size());
  for (const auto& row : r) {
    out.push_back({row[0].as<std::int64_t>(), row[1].as<std::string>(),
                   has_enc_version_ ? row[2].as<int>() : 1});
  }
  return out;
}

std::vector<NoteRow> Repository::search_notes(std::string_view term) {
  std::string like = "%" + std::string(term) + "%";
  pqxx::work txn(conn_);
  pqxx::result r =
      has_enc_version_
          ? txn.exec(
                "SELECT id, note, enc_version FROM passwords WHERE note ILIKE $1 "
                "ORDER BY id ASC",
                pqxx::params{like})
          : txn.exec(
                "SELECT id, note FROM passwords WHERE note ILIKE $1 ORDER BY id "
                "ASC",
                pqxx::params{like});
  txn.commit();
  std::vector<NoteRow> out;
  out.reserve(r.size());
  for (const auto& row : r) {
    out.push_back({row[0].as<std::int64_t>(), row[1].as<std::string>(),
                   has_enc_version_ ? row[2].as<int>() : 1});
  }
  return out;
}

std::optional<Entry> Repository::get_entry(std::int64_t id) {
  pqxx::work txn(conn_);
  pqxx::result r =
      has_enc_version_
          ? txn.exec(
                "SELECT password, note, convert_from(aes_key,'UTF8'), "
                "enc_version FROM passwords WHERE id=$1",
                pqxx::params{id})
          : txn.exec(
                "SELECT password, note, convert_from(aes_key,'UTF8') FROM "
                "passwords WHERE id=$1",
                pqxx::params{id});
  txn.commit();
  if (r.size() != 1) return std::nullopt;
  Entry e;
  e.id = id;
  e.password_blob = r[0][0].as<std::string>();
  e.note = r[0][1].as<std::string>();
  e.aes_key_armored = r[0][2].as<std::string>();
  e.enc_version = has_enc_version_ ? r[0][3].as<int>() : 1;
  return e;
}

std::int64_t Repository::insert_entry(std::string_view password_blob,
                                      std::string_view aes_key_armored,
                                      std::string_view note, int enc_version) {
  std::string pb(password_blob), ak(aes_key_armored), nt(note);
  pqxx::work txn(conn_);
  // The "v2:" blob prefix is self-describing, so omitting the column when it is
  // absent does not lose version information on read.
  pqxx::result r =
      has_enc_version_
          ? txn.exec(
                "INSERT INTO passwords (password, aes_key, note, enc_version) "
                "VALUES ($1,$2,$3,$4) RETURNING id",
                pqxx::params{pb, ak, nt, enc_version})
          : txn.exec(
                "INSERT INTO passwords (password, aes_key, note) VALUES "
                "($1,$2,$3) RETURNING id",
                pqxx::params{pb, ak, nt});
  txn.commit();
  return r[0][0].as<std::int64_t>();
}

void Repository::update_password(std::int64_t id, std::string_view password_blob,
                                 std::string_view aes_key_armored,
                                 int enc_version) {
  std::string pb(password_blob), ak(aes_key_armored);
  pqxx::work txn(conn_);
  if (has_enc_version_) {
    txn.exec(
        "UPDATE passwords SET password=$1, aes_key=$2, enc_version=$3 WHERE "
        "id=$4",
        pqxx::params{pb, ak, enc_version, id});
  } else {
    txn.exec("UPDATE passwords SET password=$1, aes_key=$2 WHERE id=$3",
             pqxx::params{pb, ak, id});
  }
  txn.commit();
}

void Repository::update_note(std::int64_t id, std::string_view note) {
  std::string nt(note);
  pqxx::work txn(conn_);
  txn.exec("UPDATE passwords SET note=$1 WHERE id=$2", pqxx::params{nt, id});
  txn.commit();
}

bool Repository::delete_entry(std::int64_t id) {
  pqxx::work txn(conn_);
  pqxx::result r =
      txn.exec("DELETE FROM passwords WHERE id=$1 RETURNING id", pqxx::params{id});
  txn.commit();
  return !r.empty();
}

std::optional<std::string> Repository::find_user_by_key_or_username(
    std::string_view pubkey, std::string_view username) {
  std::string pk(pubkey), un(username);
  pqxx::work txn(conn_);
  pqxx::result r = txn.exec(
      "SELECT username FROM user_public_keys WHERE public_key=$1 OR username=$2 "
      "LIMIT 1",
      pqxx::params{pk, un});
  txn.commit();
  if (r.size() == 1) return r[0][0].as<std::string>();
  return std::nullopt;
}

void Repository::save_public_key_ref(std::string_view pubkey,
                                     std::string_view fingerprint,
                                     std::string_view username) {
  std::string pk(pubkey), fp(fingerprint), un(username);
  pqxx::work txn(conn_);
  txn.exec(
      "INSERT INTO user_public_keys (public_key, fingerprint, username) VALUES "
      "($1,$2,$3)",
      pqxx::params{pk, fp, un});
  txn.commit();
}

}  // namespace pwmgr::db
