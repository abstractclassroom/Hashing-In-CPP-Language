#include <hashlib/sha1.hpp>

#include <cstdint>
#include <iomanip>
#include <ios>
#include <istream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace hashlib {
namespace {

constexpr std::uint32_t left_rotate(std::uint32_t x, std::uint32_t n) {
  return (x << n) | (x >> (32u - n));
}

std::vector<std::uint8_t> read_all(std::istream& in) {
  std::vector<std::uint8_t> data;
  std::array<char, 4096> buf{};
  while (in) {
    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    const auto n = in.gcount();
    if (n > 0) {
      for (std::streamsize i = 0; i < n; ++i) {
        data.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(buf[static_cast<std::size_t>(i)])));
      }
    }
  }
  if (!in.eof() && in.fail()) {
    throw std::runtime_error("Failed while reading from stream");
  }
  return data;
}

std::array<std::uint8_t, 20> sha1_digest(const std::uint8_t* msg, std::size_t len) {
  // Initial hash values (H0..H4)
  std::uint32_t h0 = 0x67452301u;
  std::uint32_t h1 = 0xEFCDAB89u;
  std::uint32_t h2 = 0x98BADCFEu;
  std::uint32_t h3 = 0x10325476u;
  std::uint32_t h4 = 0xC3D2E1F0u;

  // Pre-processing: padding
  // Append '1' bit then '0' bits until length ≡ 56 (mod 64), then append length in bits as 64-bit big-endian.
  const std::uint64_t bit_len = static_cast<std::uint64_t>(len) * 8ull;

  std::vector<std::uint8_t> buffer(msg, msg + len);
  buffer.push_back(0x80u);
  while ((buffer.size() % 64) != 56) {
    buffer.push_back(0x00u);
  }
  for (int i = 7; i >= 0; --i) {
    buffer.push_back(static_cast<std::uint8_t>((bit_len >> (8 * i)) & 0xffu));
  }

  // Process blocks
  std::uint32_t w[80];
  for (std::size_t offset = 0; offset < buffer.size(); offset += 64) {
    for (int i = 0; i < 16; ++i) {
      const std::size_t j = offset + static_cast<std::size_t>(i) * 4;
      w[i] = (static_cast<std::uint32_t>(buffer[j + 0]) << 24) |
             (static_cast<std::uint32_t>(buffer[j + 1]) << 16) |
             (static_cast<std::uint32_t>(buffer[j + 2]) << 8) |
             (static_cast<std::uint32_t>(buffer[j + 3]) << 0);
    }
    for (int i = 16; i < 80; ++i) {
      w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    std::uint32_t a = h0;
    std::uint32_t b = h1;
    std::uint32_t c = h2;
    std::uint32_t d = h3;
    std::uint32_t e = h4;

    for (int i = 0; i < 80; ++i) {
      std::uint32_t f = 0;
      std::uint32_t k = 0;

      if (i < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999u;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1u;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDCu;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6u;
      }

      const std::uint32_t temp = left_rotate(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = left_rotate(b, 30);
      b = a;
      a = temp;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  std::array<std::uint8_t, 20> out{};
  const std::uint32_t words[5] = {h0, h1, h2, h3, h4};
  for (int i = 0; i < 5; ++i) {
    out[static_cast<std::size_t>(i) * 4 + 0] = static_cast<std::uint8_t>((words[i] >> 24) & 0xffu);
    out[static_cast<std::size_t>(i) * 4 + 1] = static_cast<std::uint8_t>((words[i] >> 16) & 0xffu);
    out[static_cast<std::size_t>(i) * 4 + 2] = static_cast<std::uint8_t>((words[i] >> 8) & 0xffu);
    out[static_cast<std::size_t>(i) * 4 + 3] = static_cast<std::uint8_t>((words[i] >> 0) & 0xffu);
  }
  return out;
}

std::string to_hex(const std::array<std::uint8_t, 20>& d) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (auto b : d) {
    oss << std::setw(2) << static_cast<unsigned>(b);
  }
  return oss.str();
}

} // namespace

SHA1::SHA1(std::string_view text)
    : digest_{sha1_digest(reinterpret_cast<const std::uint8_t*>(text.data()), text.size())} {}

SHA1::SHA1(std::istream& in) {
  auto bytes = read_all(in);
  digest_ = sha1_digest(bytes.data(), bytes.size());
}

std::array<std::uint8_t, 20> SHA1::digest() const {
  return digest_;
}

std::string SHA1::hex_digest() const {
  return to_hex(digest_);
}

} // namespace hashlib




