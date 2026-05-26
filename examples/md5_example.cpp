#include <hashlib/md5.hpp>
#include <hashlib/sha1.hpp>
#include <hashlib/sha256.hpp>
#include <hashlib/sha512.hpp>

#include <iostream>

int main() {
  hashlib::MD5 h{"hello world"};
  std::cout << h.hex_digest() << "\n";

  hashlib::SHA1 s{"hello world"};
  std::cout << s.hex_digest() << "\n";

  hashlib::SHA256 s256{"hello world"};
  std::cout << s256.hex_digest() << "\n";

  hashlib::SHA512 s512{"hello world"};
  std::cout << s512.hex_digest() << "\n";
  return 0;
}

