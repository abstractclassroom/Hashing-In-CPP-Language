#ifndef HASHLIB_SHA256_HPP
#define HASHLIB_SHA256_HPP

#include <array>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>

namespace hashlib {

class SHA256 {
public:
  explicit SHA256(std::string_view text);
  explicit SHA256(std::istream& in);

  std::array<std::uint8_t, 32> digest() const;
  std::string hex_digest() const;

private:
  std::array<std::uint8_t, 32> digest_{};
};

} // namespace hashlib

#endif // HASHLIB_SHA256_HPP

