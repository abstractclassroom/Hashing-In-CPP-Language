#include <hashlib/md5.hpp>

#include <gtest/gtest.h>

#include <sstream>

TEST(MD5, EmptyString) {
  hashlib::MD5 h{""};
  EXPECT_EQ(h.hex_digest(), "d41d8cd98f00b204e9800998ecf8427e");
}

TEST(MD5, ABC) {
  hashlib::MD5 h{"abc"};
  EXPECT_EQ(h.hex_digest(), "900150983cd24fb0d6963f7d28e17f72");
}

TEST(MD5, IStreamConstructor) {
  std::istringstream in("abc");
  hashlib::MD5 h{in};
  EXPECT_EQ(h.hex_digest(), "900150983cd24fb0d6963f7d28e17f72");
}

