#include <hashlib/sha512.hpp>

#include <gtest/gtest.h>

#include <sstream>

TEST(SHA512, EmptyString) {
  hashlib::SHA512 h{""};
  EXPECT_EQ(h.hex_digest(),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

TEST(SHA512, ABC) {
  hashlib::SHA512 h{"abc"};
  EXPECT_EQ(h.hex_digest(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

TEST(SHA512, IStreamConstructor) {
  std::istringstream in("abc");
  hashlib::SHA512 h{in};
  EXPECT_EQ(h.hex_digest(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

