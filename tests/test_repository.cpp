// Repository CRUD (gated): runs only against an explicit throwaway DB whose name
// contains "test" (hard guard against touching the production "pwmgr" DB):
//   PWMGR_TEST_DB="host=localhost dbname=pwmgr_test user=... password=..."
//   build/make/pwmgr_tests --gated
#include <cstdlib>
#include <string>

#include "db/repository.h"
#include "test_framework.h"

using namespace pwmgr::db;

TEST_CASE_GATED("repository CRUD round-trip (throwaway test DB only)") {
  const char* conn = std::getenv("PWMGR_TEST_DB");
  REQUIRE(conn != nullptr);
  std::string cs(conn);
  // HARD GUARD: parse the dbname token; refuse production and require a "test"
  // marker in the DB NAME itself (not just anywhere in the string).
  auto pos = cs.find("dbname=");
  REQUIRE(pos != std::string::npos);
  auto start = pos + std::string("dbname=").size();
  auto end = cs.find_first_of(" \t", start);
  std::string dbname =
      cs.substr(start, end == std::string::npos ? std::string::npos : end - start);
  REQUIRE(dbname != "pwmgr");
  REQUIRE(dbname.find("test") != std::string::npos);

  Repository repo(cs);
  REQUIRE(repo.test_connection());

  // Fresh schema for the test.
  {
    pqxx::connection c(cs);
    pqxx::work txn(c);
    txn.exec("DROP TABLE IF EXISTS passwords");
    txn.exec("DROP TABLE IF EXISTS user_public_keys");
    txn.exec(
        "CREATE TABLE passwords (id bigserial PRIMARY KEY, password text NOT "
        "NULL, aes_key bytea NOT NULL, note text NOT NULL, created_at "
        "timestamptz DEFAULT now())");
    txn.exec(
        "CREATE TABLE user_public_keys (public_key text, fingerprint text, "
        "username text)");
    txn.commit();
  }

  repo.apply_migrations();

  std::int64_t id = repo.insert_entry("v2:abc", "ARMORED", "github", 2);
  CHECK(id > 0);

  auto notes = repo.list_notes();
  CHECK_EQ(notes.size(), static_cast<std::size_t>(1));

  auto hits = repo.search_notes("git");
  CHECK_EQ(hits.size(), static_cast<std::size_t>(1));

  auto e = repo.get_entry(id);
  REQUIRE(e.has_value());
  CHECK_EQ(e->password_blob, std::string("v2:abc"));
  CHECK_EQ(e->aes_key_armored, std::string("ARMORED"));
  CHECK_EQ(e->enc_version, 2);

  repo.update_note(id, "github-renamed");
  CHECK_EQ(repo.get_entry(id)->note, std::string("github-renamed"));

  repo.update_password(id, "v2:def", "ARMORED2", 2);
  CHECK_EQ(repo.get_entry(id)->password_blob, std::string("v2:def"));

  CHECK(repo.delete_entry(id));
  CHECK(!repo.get_entry(id).has_value());
}
