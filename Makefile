# === Compiler and flags ===

# The C++ compiler to use
CXX = g++

# Compiler flags:
# -Wall: enables all common warnings
# -Wextra: enables extra warnings
# -g: include debug info (for gdb)
# -Iinclude: adds 'include' to the header search path
CXXFLAGS = -Wall -Wextra -g -Iinclude -Isrc/utils

# === Directories ===

# Source files are in 'src'
SRC_DIR = src

# Object files will go into 'build'
BUILD_DIR = build

# Header files (if you store .h files separately)
INCLUDE_DIR = include

# === Source & Object Files ===

# Find all .cpp files in src/ (flat, non-recursive)
SOURCES = $(wildcard $(SRC_DIR)/*.cpp) \
          $(wildcard $(SRC_DIR)/utils/*.cpp) \
          $(wildcard $(SRC_DIR)/screens/*.cpp)

# Convert source filenames to build/*.o object files
# E.g., src/main.cpp -> build/main.o
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SOURCES))

# The final binary will be called 'main' and placed in build/
TARGET = $(BUILD_DIR)/main

# === Default target ===
# Typing `make` will build the main executable
all: $(TARGET)

# === Link step ===
# Combine all object files into a single executable
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^

# === Compile step ===
# Compile each .cpp to a .o file in build/
# $< = source file, $@ = target object file
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)  # Ensure the directory exists before compiling
	$(CXX) $(CXXFLAGS) -c $< -o $@

# === Create build dir if missing ===
# Ensures build/ exists before compiling
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# === Clean ===
# Run `make clean` to delete all built files
clean:
	rm -rf $(BUILD_DIR)

# === Mark targets as 'phony' ===
# These are not real files, just labels for commands
.PHONY: all clean

