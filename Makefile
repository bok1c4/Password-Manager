# === Compiler and flags ===

CXX = g++
CXXFLAGS = -Wall -Wextra -g -std=c++17 \
           -Iinclude \
           -Isrc/utils \
           -Iinclude/dotenv-cpp/include  # dotenv-cpp headers

# Use pkg-config to get linker and include flags for libpqxx and libpq
PKG_CONFIG = pkg-config
LIBS = $(shell $(PKG_CONFIG) --libs libpqxx libpq)
INCLUDES = $(shell $(PKG_CONFIG) --cflags libpqxx)

# === Directories ===

SRC_DIR = src
DOTENV_SRC_DIR = include/dotenv-cpp/src/laserpants/dotenv
DOTENV_BUILD_DIR = build/dotenv
BUILD_DIR = build
INCLUDE_DIR = include

# === Sources ===

SOURCES = $(wildcard $(SRC_DIR)/*.cpp) \
          $(wildcard $(SRC_DIR)/utils/*.cpp) \
          $(wildcard $(SRC_DIR)/screens/*.cpp)

DOTENV_SOURCES = $(wildcard $(DOTENV_SRC_DIR)/*.cpp)

# Object files for your source files
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SOURCES))

# Object files for dotenv-cpp sources
DOTENV_OBJECTS = $(patsubst $(DOTENV_SRC_DIR)/%.cpp, $(DOTENV_BUILD_DIR)/%.o, $(DOTENV_SOURCES))

TARGET = $(BUILD_DIR)/main

# === Build Rules ===

all: $(TARGET)

# Link all objects including dotenv
$(TARGET): $(OBJECTS) $(DOTENV_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# Compile your source files to object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Compile dotenv-cpp source files to object files
$(DOTENV_BUILD_DIR)/%.o: $(DOTENV_SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -Iinclude/dotenv-cpp/include -c $< -o $@

# === Clean ===

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean

