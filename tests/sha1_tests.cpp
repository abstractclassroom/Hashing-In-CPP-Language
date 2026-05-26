#include <hashlib/sha1.hpp>

#include <gtest/gtest.h>

#include <sstream>

TEST(SHA1, EmptyString) {
  hashlib::SHA1 h{""};
  EXPECT_EQ(h.hex_digest(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

TEST(SHA1, ABC) {
  hashlib::SHA1 h{"abc"};
  EXPECT_EQ(h.hex_digest(), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

TEST(SHA1, IStreamConstructor) {
  std::istringstream in("abc");
  hashlib::SHA1 h{in};
  EXPECT_EQ(h.hex_digest(), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

