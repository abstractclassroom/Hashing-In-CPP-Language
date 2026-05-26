#ifndef HASHLIB_SHA1_HPP
#define HASHLIB_SHA1_HPP

#include <array>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>

namespace hashlib {

class SHA1 {
public:
  explicit SHA1(std::string_view text);
  explicit SHA1(std::istream& in);

  std::array<std::uint8_t, 20> digest() const;
  std::string hex_digest() const;

private:
  std::array<std::uint8_t, 20> digest_{};
};

} // namespace hashlib

#endif // HASHLIB_SHA1_HPP


