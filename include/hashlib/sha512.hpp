#ifndef HASHLIB_SHA512_HPP
#define HASHLIB_SHA512_HPP

#include <array>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>

namespace hashlib {

class SHA512 {
public:
  explicit SHA512(std::string_view text);
  explicit SHA512(std::istream& in);

  std::array<std::uint8_t, 64> digest() const;
  std::string hex_digest() const;

private:
  std::array<std::uint8_t, 64> digest_{};
};

} // namespace hashlib

#endif // HASHLIB_SHA512_HPP

