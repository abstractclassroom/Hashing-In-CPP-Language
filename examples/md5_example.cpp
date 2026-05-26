#include <hashlib/md5.hpp>

#include <iostream>

int main() {
  hashlib::MD5 h{"hello world"};
  std::cout << h.hex_digest() << "\n";
  return 0;
}

