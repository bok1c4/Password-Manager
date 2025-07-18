# === Compiler and Flags ===

CXX = g++
CXXFLAGS = -Wall -Wextra -g -std=c++17 \
           -Iinclude \
           -Isrc/utils

# Use pkg-config to get proper flags for all libraries
PKG_CONFIG = pkg-config
INCLUDES = $(shell $(PKG_CONFIG) --cflags libpqxx libpq gpgme)
LIBS     = $(shell $(PKG_CONFIG) --libs libpqxx libpq gpgme)

# === Directories ===

SRC_DIR = src
BUILD_DIR = build

# === Source Files ===

SOURCES = $(wildcard $(SRC_DIR)/*.cpp) \
          $(wildcard $(SRC_DIR)/utils/*.cpp) \
          $(wildcard $(SRC_DIR)/screens/*.cpp)

OBJECTS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SOURCES))

# === Target ===

TARGET = $(BUILD_DIR)/main

# === Build Rules ===

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# === Clean ===

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean

