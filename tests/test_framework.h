// Tiny self-contained test framework (no external dependency, no network).
// Supports CHECK/REQUIRE assertions, exception checks, and a --no-gated flag so
// tests that need real secrets / a live DB (passphrase, PWMGR_TEST_DB) are
// skipped in CI but run on demand.
#pragma once
#include <cstdio>
#include <cstring>
#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace tf {

struct TestCase {
  std::string name;
  bool gated;
  std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> r;
  return r;
}

struct Registrar {
  Registrar(const char* name, bool gated, std::function<void()> fn) {
    registry().push_back({name, gated, std::move(fn)});
  }
};

struct State {
  int checks = 0;
  int failures = 0;
  std::string current;
};
inline State& state() {
  static State s;
  return s;
}

struct AssertionFailure : std::exception {};

inline void report_fail(const char* file, int line, const std::string& expr) {
  state().failures++;
  std::printf("    [FAIL] %s:%d: %s\n", file, line, expr.c_str());
}

inline bool g_run_gated = false;

inline int run(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--gated") == 0) g_run_gated = true;
    if (std::strcmp(argv[i], "--no-gated") == 0) g_run_gated = false;
  }
  int passed = 0, failed = 0, skipped = 0;
  for (auto& tc : registry()) {
    if (tc.gated && !g_run_gated) {
      std::printf("[SKIP] %s (gated; pass --gated to run)\n", tc.name.c_str());
      skipped++;
      continue;
    }
    state().current = tc.name;
    int before = state().failures;
    std::printf("[ RUN] %s\n", tc.name.c_str());
    try {
      tc.fn();
    } catch (const AssertionFailure&) {
      // already reported
    } catch (const std::exception& e) {
      report_fail(__FILE__, __LINE__,
                  std::string("unexpected exception: ") + e.what());
    } catch (...) {
      report_fail(__FILE__, __LINE__, "unexpected non-std exception");
    }
    if (state().failures == before) {
      std::printf("[ OK ] %s\n", tc.name.c_str());
      passed++;
    } else {
      std::printf("[FAILED] %s\n", tc.name.c_str());
      failed++;
    }
  }
  std::printf("\n==== %d passed, %d failed, %d skipped (%d checks) ====\n",
              passed, failed, skipped, state().checks);
  return failed == 0 ? 0 : 1;
}

}  // namespace tf

#define TF_CONCAT_(a, b) a##b
#define TF_CONCAT(a, b) TF_CONCAT_(a, b)

#define TEST_CASE(name) \
  static void TF_CONCAT(tf_test_, __LINE__)(); \
  static ::tf::Registrar TF_CONCAT(tf_reg_, __LINE__)( \
      name, false, &TF_CONCAT(tf_test_, __LINE__)); \
  static void TF_CONCAT(tf_test_, __LINE__)()

// A gated test only runs with --gated (needs real secrets / live DB).
#define TEST_CASE_GATED(name) \
  static void TF_CONCAT(tf_test_, __LINE__)(); \
  static ::tf::Registrar TF_CONCAT(tf_reg_, __LINE__)( \
      name, true, &TF_CONCAT(tf_test_, __LINE__)); \
  static void TF_CONCAT(tf_test_, __LINE__)()

#define CHECK(expr) \
  do { \
    ::tf::state().checks++; \
    if (!(expr)) ::tf::report_fail(__FILE__, __LINE__, "CHECK(" #expr ")"); \
  } while (0)

#define REQUIRE(expr) \
  do { \
    ::tf::state().checks++; \
    if (!(expr)) { \
      ::tf::report_fail(__FILE__, __LINE__, "REQUIRE(" #expr ")"); \
      throw ::tf::AssertionFailure{}; \
    } \
  } while (0)

#define CHECK_EQ(a, b) \
  do { \
    ::tf::state().checks++; \
    if (!((a) == (b))) \
      ::tf::report_fail(__FILE__, __LINE__, "CHECK_EQ(" #a ", " #b ")"); \
  } while (0)

#define CHECK_THROWS(expr) \
  do { \
    ::tf::state().checks++; \
    bool threw = false; \
    try { \
      (void)(expr); \
    } catch (...) { \
      threw = true; \
    } \
    if (!threw) \
      ::tf::report_fail(__FILE__, __LINE__, "CHECK_THROWS(" #expr ")"); \
  } while (0)
