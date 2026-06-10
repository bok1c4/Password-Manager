#include <string>

#include "db/device.h"
#include "test_framework.h"

using namespace pwmgr::db;

namespace {
const std::string kFpr = "29974BE04FCC7C31C4D1493730D6A019C21A600C";
}

TEST_CASE("fingerprint: exactly 40 hex chars accepted, either case") {
  CHECK(is_valid_fingerprint(kFpr));
  CHECK(is_valid_fingerprint("29974be04fcc7c31c4d1493730d6a019c21a600c"));
}

TEST_CASE("fingerprint: wrong length / non-hex / embedded space rejected") {
  CHECK(!is_valid_fingerprint(""));
  CHECK(!is_valid_fingerprint(kFpr.substr(0, 39)));   // 39 chars
  CHECK(!is_valid_fingerprint(kFpr + "0"));           // 41 chars
  std::string nonhex = kFpr;
  nonhex[0] = 'G';
  CHECK(!is_valid_fingerprint(nonhex));
  std::string spaced = kFpr;
  spaced[20] = ' ';  // still 40 chars, but a space is not hex
  CHECK(!is_valid_fingerprint(spaced));
}

TEST_CASE("normalize_fingerprint: gpg space-grouped display form -> canonical") {
  CHECK_EQ(normalize_fingerprint(
               "2997 4BE0 4FCC 7C31 C4D1  4937 30D6 A019 C21A 600C"),
           kFpr);
  CHECK_EQ(normalize_fingerprint("29974be04fcc7c31c4d1493730d6a019c21a600c"),
           kFpr);
  CHECK_EQ(normalize_fingerprint(kFpr), kFpr);
}

TEST_CASE("normalize_fingerprint: invalid input -> empty string") {
  CHECK_EQ(normalize_fingerprint(""), std::string());
  CHECK_EQ(normalize_fingerprint("not a fingerprint"), std::string());
  CHECK_EQ(normalize_fingerprint(kFpr.substr(0, 39)), std::string());
  CHECK_EQ(normalize_fingerprint(kFpr + "FF"), std::string());
}
