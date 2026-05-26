#include <hashlib/sha256.hpp>

#include <gtest/gtest.h>

#include <sstream>

TEST(SHA256, EmptyString) {
  hashlib::SHA256 h{""};
  EXPECT_EQ(h.hex_digest(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(SHA256, ABC) {
  hashlib::SHA256 h{"abc"};
  EXPECT_EQ(h.hex_digest(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(SHA256, IStreamConstructor) {
  std::istringstream in("abc");
  hashlib::SHA256 h{in};
  EXPECT_EQ(h.hex_digest(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

