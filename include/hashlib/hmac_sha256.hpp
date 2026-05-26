#ifndef HASHLIB_HMAC_SHA256_HPP
#define HASHLIB_HMAC_SHA256_HPP

#include <array>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>

namespace hashlib {

// HMAC_SHA256 is a small wrapper around SHA256 implementing the HMAC construction.
// It is implemented in a one-shot style (reads the full message) to match the
// rest of this teaching library.
class HMAC_SHA256 {
public:
  HMAC_SHA256(std::string_view key, std::string_view message);
  HMAC_SHA256(std::string_view key, std::istream& message);

  std::array<std::uint8_t, 32> digest() const;
  std::string hex_digest() const;

private:
  std::array<std::uint8_t, 32> digest_{};
};

} // namespace hashlib

#endif // HASHLIB_HMAC_SHA256_HPP

