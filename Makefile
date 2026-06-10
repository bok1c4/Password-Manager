# Convenience build for environments without CMake (CMakeLists.txt is the
# primary, documented build). Same targets: pwmgr_core objects -> pwmgr + pwmgr_tests.
CXX      ?= g++
CXXSTD    = -std=c++20
WARN      = -Wall -Wextra -Wpedantic -Wshadow
BUILD     = build/make

INCLUDES  = -Isrc/core -Isrc/cli -Itests -Iinclude
PKG_CFLAGS = $(shell pkg-config --cflags libpqxx libpq gpgme)
PKG_LIBS   = $(shell pkg-config --libs libpqxx libpq gpgme)
SSL_LIBS   = -lcrypto

CXXFLAGS  = $(CXXSTD) $(WARN) -g -O0 $(INCLUDES) $(PKG_CFLAGS)
LDLIBS    = $(PKG_LIBS) $(SSL_LIBS)

CORE_SRC  = $(wildcard src/core/*/*.cpp)
CLI_SRC   = $(wildcard src/cli/*.cpp src/cli/screens/*.cpp)
TEST_SRC  = $(wildcard tests/*.cpp)

CORE_OBJ  = $(patsubst %.cpp,$(BUILD)/%.o,$(CORE_SRC))
CLI_OBJ   = $(patsubst %.cpp,$(BUILD)/%.o,$(CLI_SRC))
TEST_OBJ  = $(patsubst %.cpp,$(BUILD)/%.o,$(TEST_SRC))

all: $(BUILD)/pwmgr $(BUILD)/pwmgr_tests

$(BUILD)/pwmgr: $(CORE_OBJ) $(CLI_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/pwmgr_tests: $(CORE_OBJ) $(TEST_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: $(BUILD)/pwmgr_tests
	$(BUILD)/pwmgr_tests --no-gated

# Sandboxed bash tests for the network-tooling scripts (no system contact).
test-scripts:
	bash tests/scripts/test_network_scripts.sh

clean:
	rm -rf $(BUILD)

.PHONY: all test test-scripts clean
