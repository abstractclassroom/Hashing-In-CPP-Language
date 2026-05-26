#include <hashlib/hashlib.hpp>
#include <hashlib/md5.hpp>
#include <hashlib/sha1.hpp>

#include <istream>
#include <stdexcept>

namespace hashlib {

std::string hash_hex(Algorithm alg, std::string_view text) {
  switch (alg) {
    case Algorithm::MD5:
      return MD5{text}.hex_digest();
    case Algorithm::SHA1:
      return SHA1{text}.hex_digest();
  }
  throw std::invalid_argument("Unsupported algorithm");
}

std::string hash_hex(Algorithm alg, std::istream& in) {
  switch (alg) {
    case Algorithm::MD5:
      return MD5{in}.hex_digest();
    case Algorithm::SHA1:
      return SHA1{in}.hex_digest();
  }
  throw std::invalid_argument("Unsupported algorithm");
}

} // namespace hashlib

