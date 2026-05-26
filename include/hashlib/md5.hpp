#ifndef HASHLIB_MD5_HPP
#define HASHLIB_MD5_HPP

#include <array>
#include <cstdint>
#include <iosfwd> //forward declaration of std::istream
#include <string>
#include <string_view>

namespace hashlib {

class MD5 {
public:
  explicit MD5(std::string_view text);
  explicit MD5(std::istream& in);

  std::array<std::uint8_t, 16> digest() const;
  std::string hex_digest() const;

private:
  std::array<std::uint8_t, 16> digest_{};
};

} // namespace hashlib

#endif // HASHLIB_MD5_HPP

