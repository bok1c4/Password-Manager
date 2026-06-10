// Multi-device data layer (gated): migration v2, probe, device/wrap API.
// Runs only against an explicit throwaway DB whose NAME contains "test"
// (same hard guard as test_repository.cpp):
//   PWMGR_TEST_DB="host=localhost dbname=pwmgr_test user=... password=..."
//   build/make/pwmgr_tests --gated
#include <cstdlib>
#include <string>
#include <vector>

#include "db/repository.h"
#include "test_framework.h"

using namespace pwmgr::db;

namespace {

const std::string kFprA = "29974BE04FCC7C31C4D1493730D6A019C21A600C";
const std::string kFprB = "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333";

// HARD GUARD (copied from test_repository.cpp): parse the dbname token;
// refuse production and require a "test" marker in the DB NAME itself.
std::string guarded_conn() {
  const char* conn = std::getenv("PWMGR_TEST_DB");
  REQUIRE(conn != nullptr);
  std::string cs(conn);
  auto pos = cs.find("dbname=");
  REQUIRE(pos != std::string::npos);
  auto start = pos + std::string("dbname=").size();
  auto end = cs.find_first_of(" \t", start);
  std::string dbname =
      cs.substr(start, end == std::string::npos ? std::string::npos : end - start);
  REQUIRE(dbname != "pwmgr");
  REQUIRE(dbname.find("test") != std::string::npos);
  return cs;
}

// Fresh base (pre-v2) schema. Drop order respects the FK chain — password_keys
// references both other tables, so it must go first or the later DROPs fail on
// every run after the first migration. Runs BEFORE constructing Repository so
// both ctor probes see the intended state.
void reset_base_schema(const std::string& cs) {
  pqxx::connection c(cs);
  pqxx::work txn(c);
  txn.exec("DROP TABLE IF EXISTS password_keys CASCADE");
  txn.exec("DROP TABLE IF EXISTS devices CASCADE");
  txn.exec("DROP TABLE IF EXISTS passwords CASCADE");
  txn.exec("DROP TABLE IF EXISTS user_public_keys, schema_migrations CASCADE");
  txn.exec(
      "CREATE TABLE passwords (id bigserial PRIMARY KEY, password text NOT "
      "NULL, aes_key bytea NOT NULL, note text NOT NULL, created_at "
      "timestamptz DEFAULT now())");
  txn.exec(
      "CREATE TABLE user_public_keys (public_key text, fingerprint text, "
      "username text)");
  txn.commit();
}

void seed_legacy_row(const std::string& cs, const std::string& blob,
                     const std::string& aes_key, const std::string& note) {
  pqxx::connection c(cs);
  pqxx::work txn(c);
  txn.exec("INSERT INTO passwords (password, aes_key, note) VALUES ($1,$2,$3)",
           pqxx::params{blob, aes_key, note});
  txn.commit();
}

// The byte-identity snapshot: every column that existed pre-migration.
std::string snapshot_passwords(const std::string& cs) {
  pqxx::connection c(cs);
  pqxx::work txn(c);
  pqxx::result r = txn.exec(
      "SELECT id, password, convert_from(aes_key,'UTF8'), note FROM passwords "
      "ORDER BY id");
  txn.commit();
  std::string out;
  for (const auto& row : r) {
    out += row[0].as<std::string>() + "|" + row[1].as<std::string>() + "|" +
           row[2].as<std::string>() + "|" + row[3].as<std::string>() + "\n";
  }
  return out;
}

std::int64_t count_rows(const std::string& cs, const std::string& table) {
  pqxx::connection c(cs);
  pqxx::work txn(c);
  auto r = txn.exec("SELECT count(*) FROM " + table);
  txn.commit();
  return r[0][0].as<std::int64_t>();
}

}  // namespace

TEST_CASE_GATED("devices: unmigrated DB probes false") {
  std::string cs = guarded_conn();
  reset_base_schema(cs);
  Repository repo(cs);
  CHECK(!repo.has_device_tables());
  // Raw-SQL cross-check that neither table exists.
  pqxx::connection c(cs);
  pqxx::work txn(c);
  auto r = txn.exec(
      "SELECT count(*) FROM information_schema.tables WHERE table_schema = "
      "current_schema() AND table_name IN ('devices','password_keys')");
  txn.commit();
  CHECK_EQ(r[0][0].as<int>(), 0);
}

TEST_CASE_GATED("devices: migration v2 registers founding + backfills; idempotent") {
  std::string cs = guarded_conn();
  reset_base_schema(cs);
  seed_legacy_row(cs, "legacyblob1", "ARMORED-WRAP-1", "site-one");
  seed_legacy_row(cs, "legacyblob2", "ARMORED-WRAP-2", "site-two");
  const std::string before = snapshot_passwords(cs);

  Repository repo(cs);
  repo.apply_migrations();
  // Lower-case, space-grouped input must be normalized on registration.
  FoundingDevice founding{"deviceA",
                          "2997 4be0 4fcc 7c31 c4d1 4937 30d6 a019 c21a 600c",
                          "PUBKEY-A"};
  repo.apply_migrations_v2(founding);
  CHECK(repo.has_device_tables());
  CHECK_EQ(count_rows(cs, "devices"), 1);
  CHECK_EQ(count_rows(cs, "password_keys"), 2);
  {
    pqxx::connection c(cs);
    pqxx::work txn(c);
    auto r = txn.exec("SELECT name, fingerprint, status FROM devices");
    CHECK_EQ(r[0][0].as<std::string>(), std::string("deviceA"));
    CHECK_EQ(r[0][1].as<std::string>(), kFprA);
    CHECK_EQ(r[0][2].as<std::string>(), std::string("active"));
    // Backfilled wrap content is byte-equal to the legacy aes_key.
    auto w = txn.exec(
        "SELECT convert_from(pk.wrapped_key,'UTF8') FROM password_keys pk "
        "JOIN passwords p ON p.id = pk.password_id ORDER BY p.id");
    txn.commit();
    CHECK_EQ(w[0][0].as<std::string>(), std::string("ARMORED-WRAP-1"));
    CHECK_EQ(w[1][0].as<std::string>(), std::string("ARMORED-WRAP-2"));
  }

  // Idempotent: run again, nothing changes.
  repo.apply_migrations_v2(founding);
  CHECK_EQ(count_rows(cs, "devices"), 1);
  CHECK_EQ(count_rows(cs, "password_keys"), 2);

  // A second device running `migrate` with ITS founding identity must not
  // self-enroll (empty-table guard) nor be credited with backfill wraps.
  FoundingDevice intruder{"deviceB", kFprB, "PUBKEY-B"};
  repo.apply_migrations_v2(intruder);
  CHECK_EQ(count_rows(cs, "devices"), 1);
  CHECK_EQ(count_rows(cs, "password_keys"), 2);

  // The invariant: the passwords table is bit-identical throughout.
  CHECK_EQ(snapshot_passwords(cs), before);
}
