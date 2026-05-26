#include <hashlib/md5.hpp>

#include <array>
#include <cstdint>
#include <iomanip>
#include <istream>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace hashlib {
namespace {

// Based on the algorithm description in RFC 1321.

constexpr std::uint32_t left_rotate(std::uint32_t x, std::uint32_t c) {
  return (x << c) | (x >> (32u - c));
}

constexpr std::array<std::uint32_t, 64> k = {
  0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
  0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
  0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
  0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
  0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
  0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
  0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
  0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
  0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
  0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
  0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
  0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
  0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
  0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
  0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
  0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
};

constexpr std::array<std::uint32_t, 64> s = {
  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
};

std::vector<std::uint8_t> read_all(std::istream& in) {
  std::vector<std::uint8_t> data;
  std::array<char, 4096> buf{};
  while (in) {
    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    const auto n = in.gcount();
    if (n > 0) {
      data.insert(data.end(), reinterpret_cast<std::uint8_t*>(buf.data()),
                  reinterpret_cast<std::uint8_t*>(buf.data()) + n);
    }
  }
  if (!in.eof() && in.fail()) {
    throw std::runtime_error("Failed while reading from stream");
  }
  return data;
}

std::array<std::uint8_t, 16> md5_digest(const std::uint8_t* msg, std::size_t len) {
  // Initialize variables
  std::uint32_t a0 = 0x67452301u;
  std::uint32_t b0 = 0xefcdab89u;
  std::uint32_t c0 = 0x98badcfeu;
  std::uint32_t d0 = 0x10325476u;

  // Padding the message
  // Append a single '1' bit (0x80), then pad with zeros until length ≡ 56 (mod 64)
  // Append length in bits as 64-bit using little-endian orientation.
  const std::uint64_t bit_len = static_cast<std::uint64_t>(len) * 8ull;

  std::vector<std::uint8_t> buffer(msg, msg + len);
  buffer.push_back(0x80u);
  while ((buffer.size() % 64) != 56) {
    buffer.push_back(0x00u);
  }

  for (int i = 0; i < 8; ++i) {
    buffer.push_back(static_cast<std::uint8_t>((bit_len >> (8 * i)) & 0xffu));
  }

  // Successive 512-bit chunks
  for (std::size_t offset = 0; offset < buffer.size(); offset += 64) {
    // Chunk into sixteen 32-bit words w[j], little-endian
    std::uint32_t w[16];
    for (int j = 0; j < 16; ++j) {
      const std::size_t i = offset + static_cast<std::size_t>(j) * 4;
      w[j] = (static_cast<std::uint32_t>(buffer[i + 0]) << 0) |
             (static_cast<std::uint32_t>(buffer[i + 1]) << 8) |
             (static_cast<std::uint32_t>(buffer[i + 2]) << 16) |
             (static_cast<std::uint32_t>(buffer[i + 3]) << 24);
    }

    std::uint32_t A = a0;
    std::uint32_t B = b0;
    std::uint32_t C = c0;
    std::uint32_t D = d0;

    for (std::uint32_t i = 0; i < 64; ++i) {
      std::uint32_t F = 0;
      std::uint32_t g = 0;

      if (i < 16) {
        F = (B & C) | ((~B) & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | ((~D) & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | (~D));
        g = (7 * i) % 16;
      }

      const std::uint32_t tmp = D;
      D = C;
      C = B;
      B = B + left_rotate(A + F + k[i] + w[g], s[i]);
      A = tmp;
    }

    a0 += A;
    b0 += B;
    c0 += C;
    d0 += D;
  }

  std::array<std::uint8_t, 16> out{};
  const std::uint32_t words[4] = {a0, b0, c0, d0};
  for (int i = 0; i < 4; ++i) {
    out[static_cast<std::size_t>(i) * 4 + 0] = static_cast<std::uint8_t>((words[i] >> 0) & 0xffu);
    out[static_cast<std::size_t>(i) * 4 + 1] = static_cast<std::uint8_t>((words[i] >> 8) & 0xffu);
    out[static_cast<std::size_t>(i) * 4 + 2] = static_cast<std::uint8_t>((words[i] >> 16) & 0xffu);
    out[static_cast<std::size_t>(i) * 4 + 3] = static_cast<std::uint8_t>((words[i] >> 24) & 0xffu);
  }
  return out;
}

std::string to_hex(const std::array<std::uint8_t, 16>& d) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (auto b : d) {
    oss << std::setw(2) << static_cast<unsigned>(b);
  }
  return oss.str();
}

} // namespace

MD5::MD5(std::string_view text)
    : digest_{md5_digest(reinterpret_cast<const std::uint8_t*>(text.data()), text.size())} {}

MD5::MD5(std::istream& in) {
  auto bytes = read_all(in);
  digest_ = md5_digest(bytes.data(), bytes.size());
}

std::array<std::uint8_t, 16> MD5::digest() const {
  return digest_;
}

std::string MD5::hex_digest() const {
  return to_hex(digest_);
}

} // namespace hashlib


