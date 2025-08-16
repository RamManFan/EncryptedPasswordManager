cmake_minimum_required(VERSION 3.20)
project(EncryptedPasswordManager LANGUAGES CXX)

# ---- Language / build basics
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Prefer UCRT64; you already pass -DCMAKE_PREFIX_PATH=/ucrt64 but we add both styles
list(PREPEND CMAKE_PREFIX_PATH "/ucrt64" "C:/msys64/ucrt64")

# ---- Dependencies
find_package(OpenSSL REQUIRED)        # Provides OpenSSL::Crypto (and ::SSL)
find_package(SQLite3 REQUIRED)        # Provides SQLite::SQLite3

# --- Argon2 robust discovery (MSYS2 UCRT64 ships header+lib, but no pkg-config .pc)
# Try both MSYS and Windows-style prefixes
set(_UCRT64_PREFIX_CMAKE_STYLE "/ucrt64")
set(_UCRT64_PREFIX_WIN_STYLE   "C:/msys64/ucrt64")

# 1) Try find_path/find_library across both prefixes (no-default-path first)
find_path(ARGON2_INCLUDE_DIR
    NAMES argon2.h
    HINTS
        "${_UCRT64_PREFIX_CMAKE_STYLE}/include"
        "${_UCRT64_PREFIX_WIN_STYLE}/include"
    NO_DEFAULT_PATH
)
find_library(ARGON2_LIBRARY
    NAMES argon2
    HINTS
        "${_UCRT64_PREFIX_CMAKE_STYLE}/lib"
        "${_UCRT64_PREFIX_WIN_STYLE}/lib"
    NO_DEFAULT_PATH
)

# 2) If still not found, allow defaults as a second attempt
if (NOT ARGON2_INCLUDE_DIR)
  find_path(ARGON2_INCLUDE_DIR NAMES argon2.h
            HINTS "${_UCRT64_PREFIX_CMAKE_STYLE}/include" "${_UCRT64_PREFIX_WIN_STYLE}/include")
endif()
if (NOT ARGON2_LIBRARY)
  find_library(ARGON2_LIBRARY NAMES argon2
               HINTS "${_UCRT64_PREFIX_CMAKE_STYLE}/lib" "${_UCRT64_PREFIX_WIN_STYLE}/lib")
endif()

# 3) Final fallback: if files exist at known locations, set them directly
if (NOT ARGON2_INCLUDE_DIR)
  if (EXISTS "/ucrt64/include/argon2.h")
    set(ARGON2_INCLUDE_DIR "/ucrt64/include")
  elseif (EXISTS "C:/msys64/ucrt64/include/argon2.h")
    set(ARGON2_INCLUDE_DIR "C:/msys64/ucrt64/include")
  endif()
endif()

if (NOT ARGON2_LIBRARY)
  if (EXISTS "/ucrt64/lib/libargon2.dll.a")
    set(ARGON2_LIBRARY "/ucrt64/lib/libargon2.dll.a")
  elseif (EXISTS "C:/msys64/ucrt64/lib/libargon2.dll.a")
    set(ARGON2_LIBRARY "C:/msys64/ucrt64/lib/libargon2.dll.a")
  elseif (EXISTS "/ucrt64/lib/libargon2.a")
    set(ARGON2_LIBRARY "/ucrt64/lib/libargon2.a")
  elseif (EXISTS "C:/msys64/ucrt64/lib/libargon2.a")
    set(ARGON2_LIBRARY "C:/msys64/ucrt64/lib/libargon2.a")
  endif()
endif()

message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto lib: ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "SQLite3 include: ${SQLite3_INCLUDE_DIRS}")
message(STATUS "SQLite3 lib: ${SQLite3_LIBRARIES}")
message(STATUS "Argon2 include: ${ARGON2_INCLUDE_DIR}")
message(STATUS "Argon2 lib: ${ARGON2_LIBRARY}")

if (NOT ARGON2_INCLUDE_DIR OR NOT ARGON2_LIBRARY)
  message(FATAL_ERROR "Argon2 not found. Ensure 'mingw-w64-ucrt-x86_64-argon2' is installed. "
                      "Looked in /ucrt64 and C:/msys64/ucrt64.")
endif()

# ---- Targets
# ---- Core library with app sources
add_library(epm_core STATIC
    src/AuthManager.cpp
    src/DatabaseManager.cpp
    src/EncryptionManager.cpp   
)


target_include_directories(epm_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${ARGON2_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(epm_core PUBLIC
    SQLite::SQLite3
    OpenSSL::Crypto
    ${ARGON2_LIBRARY}
)

# ---- App executable (only main.cpp)
add_executable(epm src/main.cpp)
target_link_libraries(epm PRIVATE epm_core)

# ---- Tests
find_package(Catch2 3 QUIET)
if(NOT Catch2_FOUND)
  include(FetchContent)
  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.4
  )
  FetchContent_MakeAvailable(Catch2)
endif()


add_executable(tests
  tests/placeholder.cpp
  tests/auth_gate.cpp
  tests/db_master.cpp
  tests/db_kdf.cpp         
  tests/crypto_gcm.cpp
  tests/cred_roundtrip.cpp
)


target_link_libraries(tests PRIVATE
  epm_core
  Catch2::Catch2WithMain
)

