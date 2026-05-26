include(FetchContent)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

add_executable(hashlib_tests
  md5_tests.cpp
  sha1_tests.cpp
  sha256_tests.cpp
)

target_link_libraries(hashlib_tests
  PRIVATE
    hashlib::hashlib
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(hashlib_tests)


