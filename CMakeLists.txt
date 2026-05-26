cmake_minimum_required(VERSION 3.20)

project(hashlib VERSION 0.1.0 LANGUAGES CXX)

option(HASHLIB_BUILD_TESTS "Build unit tests" ON)
option(HASHLIB_BUILD_EXAMPLES "Build examples" ON)

add_library(hashlib
  src/md5.cpp
  src/sha1.cpp
  src/sha256.cpp
  src/sha512.cpp
  src/hmac_sha256.cpp
  src/hashlib.cpp
)

add_library(hashlib::hashlib ALIAS hashlib)

target_include_directories(hashlib
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(hashlib PUBLIC cxx_std_17)

if (MSVC)
  target_compile_options(hashlib PRIVATE /W4)
else()
  target_compile_options(hashlib PRIVATE -Wall -Wextra -Wpedantic)
endif()

if (HASHLIB_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if (HASHLIB_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

