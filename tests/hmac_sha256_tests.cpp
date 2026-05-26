#include <hashlib/hmac_sha256.hpp>

#include <gtest/gtest.h>

#include <sstream>
#include <string>

// RFC 4231 test vectors
TEST(HMAC_SHA256, RFC4231_TestCase1) {
  const std::string key(20, static_cast<char>(0x0b));
  const std::string msg = "Hi There";

  hashlib::HMAC_SHA256 h{key, msg};
  EXPECT_EQ(h.hex_digest(), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST(HMAC_SHA256, RFC4231_TestCase2) {
  const std::string key = "Jefe";
  const std::string msg = "what do ya want for nothing?";

  hashlib::HMAC_SHA256 h{key, msg};
  EXPECT_EQ(h.hex_digest(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST(HMAC_SHA256, IStreamConstructor) {
  const std::string key = "key";

  // Use a common known value (can be checked with openssl):
  // echo -n "The quick brown fox jumps over the lazy dog" | \
  //   openssl dgst -sha256 -hmac "key"
  const std::string expected = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";

  std::istringstream in("The quick brown fox jumps over the lazy dog");
  hashlib::HMAC_SHA256 h{key, in};
  EXPECT_EQ(h.hex_digest(), expected);
}


