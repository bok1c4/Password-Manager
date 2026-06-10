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

TEST_CASE_GATED("devices: unmigrated degradation contract") {
  std::string cs = guarded_conn();
  reset_base_schema(cs);
  seed_legacy_row(cs, "legacyblob", "LEGACY-SENTINEL", "site");
  Repository repo(cs);
  REQUIRE(!repo.has_device_tables());

  CHECK(repo.list_devices().empty());
  CHECK(repo.active_devices().empty());
  CHECK(!repo.founding_device().has_value());
  CHECK(repo.entry_ids_wrapped_for(1).empty());
  auto wrap = repo.wrapped_key_for(1, kFprA);
  REQUIRE(wrap.has_value());
  CHECK_EQ(*wrap, std::string("LEGACY-SENTINEL"));
  CHECK(!repo.revoke_device("anything"));
  CHECK_THROWS(repo.add_device({0, "x", kFprB, "PK", "active", ""}));
  CHECK_THROWS(repo.insert_wrapped_key(1, 1, "W"));
  CHECK_THROWS(repo.replace_entry_keys(1, "v2:new", "NEWWRAP", 2,
                                       {WrappedKey{1, "W"}}));
  // Empty wraps degrade to legacy-equivalent SQL.
  repo.replace_entry_keys(1, "v2:new", "NEWWRAP", 2, {});
  CHECK_EQ(*repo.wrapped_key_for(1, kFprA), std::string("NEWWRAP"));
}

TEST_CASE_GATED("devices: three read shapes + wrap API + revoke") {
  std::string cs = guarded_conn();
  reset_base_schema(cs);
  seed_legacy_row(cs, "legacyblob1", "FOUNDING-WRAP-1", "one");
  Repository repo(cs);
  repo.apply_migrations();
  repo.apply_migrations_v2({"deviceA", kFprA, "PUBKEY-A"});

  // Enroll a second device.
  std::int64_t devB = repo.add_device({0, "deviceB", kFprB, "PUBKEY-B", "", ""});
  CHECK(devB > 0);
  CHECK_EQ(repo.list_devices().size(), static_cast<std::size_t>(2));
  CHECK_EQ(repo.active_devices().size(), static_cast<std::size_t>(2));
  REQUIRE(repo.founding_device().has_value());
  CHECK_EQ(repo.founding_device()->name, std::string("deviceA"));

  // Shape 1: backfilled copy for A; legacy fallback content identical.
  CHECK_EQ(*repo.wrapped_key_for(1, kFprA), std::string("FOUNDING-WRAP-1"));
  // Shape 2: B has no wrap yet -> falls back to the legacy aes_key.
  CHECK_EQ(*repo.wrapped_key_for(1, kFprB), std::string("FOUNDING-WRAP-1"));
  // Wrap for B; now B reads its own wrap.
  repo.insert_wrapped_key(1, devB, "WRAP-FOR-B");
  CHECK_EQ(*repo.wrapped_key_for(1, kFprB), std::string("WRAP-FOR-B"));
  // Idempotent double insert: still one row, original content.
  repo.insert_wrapped_key(1, devB, "WRAP-FOR-B-DUP");
  CHECK_EQ(*repo.wrapped_key_for(1, kFprB), std::string("WRAP-FOR-B"));
  auto ids = repo.entry_ids_wrapped_for(devB);
  REQUIRE(ids.size() == 1);
  CHECK_EQ(ids[0], static_cast<std::int64_t>(1));

  // insert_entry_with_keys: one txn, wraps queryable per device.
  std::int64_t id2 = repo.insert_entry_with_keys(
      "v2:blob2", "FOUNDING-WRAP-2", "two", 2,
      {WrappedKey{repo.founding_device()->id, "A-WRAP-2"},
       WrappedKey{devB, "B-WRAP-2"}});
  CHECK(id2 > 0);
  CHECK_EQ(*repo.wrapped_key_for(id2, kFprA), std::string("A-WRAP-2"));
  CHECK_EQ(*repo.wrapped_key_for(id2, kFprB), std::string("B-WRAP-2"));

  // replace_entry_keys: atomic swap to exactly the given wraps.
  repo.replace_entry_keys(id2, "v2:blob2-rot", "FOUNDING-WRAP-2R", 2,
                          {WrappedKey{devB, "B-WRAP-2R"}});
  auto e2 = repo.get_entry(id2);
  REQUIRE(e2.has_value());
  CHECK_EQ(e2->password_blob, std::string("v2:blob2-rot"));
  CHECK_EQ(e2->aes_key_armored, std::string("FOUNDING-WRAP-2R"));
  CHECK_EQ(*repo.wrapped_key_for(id2, kFprB), std::string("B-WRAP-2R"));
  // A's wrap is gone -> falls back to the legacy column.
  CHECK_EQ(*repo.wrapped_key_for(id2, kFprA), std::string("FOUNDING-WRAP-2R"));
  // Nonexistent id throws (RETURNING guard), nothing committed.
  CHECK_THROWS(repo.replace_entry_keys(999999, "x", "y", 2, {}));

  // Revoke B: status flips, wraps deleted, reads fall back to legacy.
  CHECK(repo.revoke_device("deviceB"));
  CHECK_EQ(repo.active_devices().size(), static_cast<std::size_t>(1));
  CHECK(repo.entry_ids_wrapped_for(devB).empty());
  CHECK_EQ(*repo.wrapped_key_for(1, kFprB), std::string("FOUNDING-WRAP-1"));
  // Unknown / already-revoked names refuse.
  CHECK(!repo.revoke_device("deviceB"));
  CHECK(!repo.revoke_device("no-such-device"));

  // Malformed fingerprint rejected before any SQL.
  CHECK_THROWS(repo.add_device({0, "bad", "SHORT", "PK", "", ""}));
}
