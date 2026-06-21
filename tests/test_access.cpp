// Pure access-matrix pivots (no DB, no secrets): wraps_by_entry / count_by_device.
// These back the CMS read views (`pwmgr status`, `pwmgr entry list`) so the
// grouping/dedup/sort logic is exercised here, not only behind the gated DB tests.
#include <vector>

#include "db/repository.h"
#include "test_framework.h"

using namespace pwmgr::db;

TEST_CASE("wraps_by_entry groups, de-dups, and sorts device ids ascending") {
  // (1,20) before (1,10) and a duplicate (1,10) — input order is arbitrary.
  std::vector<WrapPair> pairs = {{1, 20}, {1, 10}, {2, 10}, {1, 10}};
  auto by = wraps_by_entry(pairs);
  REQUIRE(by.size() == static_cast<std::size_t>(2));
  REQUIRE(by[1].size() == static_cast<std::size_t>(2));
  CHECK_EQ(by[1][0], static_cast<std::int64_t>(10));  // ascending, dup collapsed
  CHECK_EQ(by[1][1], static_cast<std::int64_t>(20));
  REQUIRE(by[2].size() == static_cast<std::size_t>(1));
  CHECK_EQ(by[2][0], static_cast<std::int64_t>(10));
}

TEST_CASE("count_by_device counts DISTINCT entries per device") {
  // device 10 wraps entries 1 and 2 (the duplicate (1,10) must not double-count).
  std::vector<WrapPair> pairs = {{1, 10}, {2, 10}, {1, 10}, {3, 20}};
  auto c = count_by_device(pairs);
  CHECK_EQ(c[10], static_cast<std::int64_t>(2));
  CHECK_EQ(c[20], static_cast<std::int64_t>(1));
  CHECK_EQ(c.count(30), static_cast<std::size_t>(0));  // no wraps -> absent
}

TEST_CASE("empty matrix -> empty pivots (pre-migration / no entries)") {
  CHECK(wraps_by_entry({}).empty());
  CHECK(count_by_device({}).empty());
}
