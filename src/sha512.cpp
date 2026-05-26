#include <hashlib/sha512.hpp>

#include <cstdint>
#include <iomanip>
#include <ios>
#include <istream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace hashlib {
namespace {

constexpr std::uint64_t rotr(std::uint64_t x, std::uint64_t n) {
  return (x >> n) | (x << (64u - n));
}

constexpr std::uint64_t ch(std::uint64_t x, std::uint64_t y, std::uint64_t z) {
  return (x & y) ^ (~x & z);
}

constexpr std::uint64_t maj(std::uint64_t x, std::uint64_t y, std::uint64_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

constexpr std::uint64_t big_sigma0(std::uint64_t x) {
  return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

constexpr std::uint64_t big_sigma1(std::uint64_t x) {
  return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

constexpr std::uint64_t small_sigma0(std::uint64_t x) {
  return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
}

constexpr std::uint64_t small_sigma1(std::uint64_t x) {
  return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
}

constexpr std::uint64_t k[80] = {
  0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
  0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
  0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
  0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
  0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
  0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
  0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
  0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
  0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
  0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
  0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
  0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
  0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
  0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
  0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
  0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
  0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
  0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
  0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
  0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};

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

std::array<std::uint8_t, 64> sha512_digest(const std::uint8_t* msg, std::size_t len) {
  std::uint64_t h[8] = {
    0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
    0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull
  };

  const std::uint64_t bit_len_low = static_cast<std::uint64_t>(len) * 8ull;
  const std::uint64_t bit_len_high = 0ull; // only supports messages < 2^64 bits in this teaching implementation

  std::vector<std::uint8_t> buffer(msg, msg + len);
  buffer.push_back(0x80u);
  while ((buffer.size() % 128) != 112) {
    buffer.push_back(0x00u);
  }

  // Append 128-bit length, big-endian (high then low)
  for (int i = 7; i >= 0; --i) {
    buffer.push_back(static_cast<std::uint8_t>((bit_len_high >> (8 * i)) & 0xffu));
  }
  for (int i = 7; i >= 0; --i) {
    buffer.push_back(static_cast<std::uint8_t>((bit_len_low >> (8 * i)) & 0xffu));
  }

  std::uint64_t w[80];

  for (std::size_t offset = 0; offset < buffer.size(); offset += 128) {
    for (int i = 0; i < 16; ++i) {
      const std::size_t j = offset + static_cast<std::size_t>(i) * 8;
      w[i] = (static_cast<std::uint64_t>(buffer[j + 0]) << 56) |
             (static_cast<std::uint64_t>(buffer[j + 1]) << 48) |
             (static_cast<std::uint64_t>(buffer[j + 2]) << 40) |
             (static_cast<std::uint64_t>(buffer[j + 3]) << 32) |
             (static_cast<std::uint64_t>(buffer[j + 4]) << 24) |
             (static_cast<std::uint64_t>(buffer[j + 5]) << 16) |
             (static_cast<std::uint64_t>(buffer[j + 6]) << 8) |
             (static_cast<std::uint64_t>(buffer[j + 7]) << 0);
    }
    for (int i = 16; i < 80; ++i) {
      w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
    }

    std::uint64_t a = h[0];
    std::uint64_t b = h[1];
    std::uint64_t c = h[2];
    std::uint64_t d = h[3];
    std::uint64_t e = h[4];
    std::uint64_t f = h[5];
    std::uint64_t g = h[6];
    std::uint64_t hh = h[7];

    for (int i = 0; i < 80; ++i) {
      const std::uint64_t t1 = hh + big_sigma1(e) + ch(e, f, g) + k[i] + w[i];
      const std::uint64_t t2 = big_sigma0(a) + maj(a, b, c);

      hh = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }

  std::array<std::uint8_t, 64> out{};
  for (int i = 0; i < 8; ++i) {
    out[static_cast<std::size_t>(i) * 8 + 0] = static_cast<std::uint8_t>((h[i] >> 56) & 0xffu);
    out[static_cast<std::size_t>(i) * 8 + 1] = static_cast<std::uint8_t>((h[i] >> 48) & 0xffu);
    out[static_cast<std::size_t>(i) * 8 + 2] = static_cast<std::uint8_t>((h[i] >> 40) & 0xffu);
    out[static_cast<std::size_t>(i) * 8 + 3] = static_cast<std::uint8_t>((h[i] >> 32) & 0xffu);
    out[static_cast<std::size_t>(i) * 8 + 4] = static_cast<std::uint8_t>((h[i] >> 24) & 0xffu);
    out[static_cast<std::size_t>(i) * 8 + 5] = static_cast<std::uint8_t>((h[i] >> 16) & 0xffu);
    out[static_cast<std::size_t>(i) * 8 + 6] = static_cast<std::uint8_t>((h[i] >> 8) & 0xffu);
    out[static_cast<std::size_t>(i) * 8 + 7] = static_cast<std::uint8_t>((h[i] >> 0) & 0xffu);
  }
  return out;
}

std::string to_hex(const std::array<std::uint8_t, 64>& d) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (auto b : d) {
    oss << std::setw(2) << static_cast<unsigned>(b);
  }
  return oss.str();
}

} // namespace

SHA512::SHA512(std::string_view text)
    : digest_{sha512_digest(reinterpret_cast<const std::uint8_t*>(text.data()), text.size())} {}

SHA512::SHA512(std::istream& in) {
  auto bytes = read_all(in);
  digest_ = sha512_digest(bytes.data(), bytes.size());
}

std::array<std::uint8_t, 64> SHA512::digest() const {
  return digest_;
}

std::string SHA512::hex_digest() const {
  return to_hex(digest_);
}

} // namespace hashlib

