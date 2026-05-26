#ifndef HASHLIB_HASHLIB_HPP
#define HASHLIB_HASHLIB_HPP

#include <iosfwd>
#include <string>
#include <string_view>

namespace hashlib {

enum class Algorithm {
  MD5,
  SHA1,
};

std::string hash_hex(Algorithm alg, std::string_view text);
std::string hash_hex(Algorithm alg, std::istream& in);

} // namespace hashlib

#endif // HASHLIB_HASHLIB_HPP