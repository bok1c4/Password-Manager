cmake_minimum_required(VERSION 3.20)
project(pwmgr LANGUAGES CXX)

# libpqxx 8.x headers require C++20 (std::source_location / ranges / concepts).
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

# ---- Dependencies ----
find_package(PkgConfig REQUIRED)
pkg_check_modules(PQXX  REQUIRED IMPORTED_TARGET libpqxx)
pkg_check_modules(PQ    REQUIRED IMPORTED_TARGET libpq)
pkg_check_modules(GPGME REQUIRED IMPORTED_TARGET gpgme)
find_package(OpenSSL REQUIRED)

# Vendored single-header nlohmann::json lives in include/config/json.hpp.
add_library(pwmgr_vendor INTERFACE)
target_include_directories(pwmgr_vendor SYSTEM INTERFACE
  "${CMAKE_SOURCE_DIR}/include")

# Warnings applied to first-party targets only.
set(PWMGR_WARNINGS -Wall -Wextra -Wpedantic -Wshadow)

# ---- Core static library (crypto + db + config) ----
file(GLOB_RECURSE CORE_SRC CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/core/*.cpp")
if(CORE_SRC)
  add_library(pwmgr_core STATIC ${CORE_SRC})
  target_include_directories(pwmgr_core PUBLIC "${CMAKE_SOURCE_DIR}/src/core")
  target_compile_options(pwmgr_core PRIVATE ${PWMGR_WARNINGS})
  target_link_libraries(pwmgr_core
    PUBLIC  PkgConfig::PQXX PkgConfig::PQ PkgConfig::GPGME OpenSSL::Crypto
    PRIVATE pwmgr_vendor)
endif()

# ---- CLI executable ----
file(GLOB_RECURSE CLI_SRC CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/cli/*.cpp")
if(CLI_SRC AND TARGET pwmgr_core)
  add_executable(pwmgr ${CLI_SRC})
  target_include_directories(pwmgr PRIVATE "${CMAKE_SOURCE_DIR}/src/cli")
  target_compile_options(pwmgr PRIVATE ${PWMGR_WARNINGS})
  target_link_libraries(pwmgr PRIVATE pwmgr_core pwmgr_vendor)
endif()

# ---- Tests ----
file(GLOB TEST_SRC CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/tests/*.cpp")
if(TEST_SRC AND TARGET pwmgr_core)
  enable_testing()
  add_executable(pwmgr_tests ${TEST_SRC})
  target_include_directories(pwmgr_tests PRIVATE
    "${CMAKE_SOURCE_DIR}/tests" "${CMAKE_SOURCE_DIR}/src/core")
  target_compile_options(pwmgr_tests PRIVATE ${PWMGR_WARNINGS})
  target_link_libraries(pwmgr_tests PRIVATE pwmgr_core pwmgr_vendor)
  add_test(NAME unit COMMAND pwmgr_tests --no-gated)
endif()
