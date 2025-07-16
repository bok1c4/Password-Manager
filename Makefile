# === Compiler and flags ===

CXX = g++
CXXFLAGS = -Wall -Wextra -g -Iinclude -Isrc/utils -std=c++17

# Use pkg-config to get linker and include flags for libpqxx and libpq
PKG_CONFIG = pkg-config
LIBS = $(shell $(PKG_CONFIG) --libs libpqxx libpq)
INCLUDES = $(shell $(PKG_CONFIG) --cflags libpqxx)

# === Directories ===

SRC_DIR = src
BUILD_DIR = build
INCLUDE_DIR = include

# === Sources ===

SOURCES = $(wildcard $(SRC_DIR)/*.cpp) \
          $(wildcard $(SRC_DIR)/utils/*.cpp) \
          $(wildcard $(SRC_DIR)/screens/*.cpp)

OBJECTS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SOURCES))

TARGET = $(BUILD_DIR)/main

# === Build Rules ===

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# Compile .cpp -> .o
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# === Clean ===

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean

