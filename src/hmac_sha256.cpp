#include <hashlib/hmac_sha256.hpp>
#include <hashlib/sha256.hpp>

#include <array>
#include <cstdint>
#include <iomanip>
#include <ios>
#include <istream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace hashlib {
namespace {

constexpr std::size_t SHA256_BLOCK_BYTES = 64;

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

std::vector<std::uint8_t> to_bytes(std::string_view s) {
  std::vector<std::uint8_t> out;
  out.reserve(s.size());
  for (unsigned char c : s) {
    out.push_back(static_cast<std::uint8_t>(c));
  }
  return out;
}

std::vector<std::uint8_t> normalize_key(std::string_view key) {
  // Per HMAC spec: if key is longer than block size, replace it with H(key).
  // Then pad with zeros to block size.
  std::vector<std::uint8_t> k0 = to_bytes(key);

  if (k0.size() > SHA256_BLOCK_BYTES) {
    const auto dk = SHA256{key}.digest();
    k0.assign(dk.begin(), dk.end());
  }

  k0.resize(SHA256_BLOCK_BYTES, 0x00u);
  return k0;
}

std::array<std::uint8_t, 32> hmac_sha256(std::string_view key, const std::uint8_t* msg, std::size_t msg_len) {
  const auto k0 = normalize_key(key);

  std::array<std::uint8_t, SHA256_BLOCK_BYTES> ipad{};
  std::array<std::uint8_t, SHA256_BLOCK_BYTES> opad{};
  for (std::size_t i = 0; i < SHA256_BLOCK_BYTES; ++i) {
    ipad[i] = static_cast<std::uint8_t>(k0[i] ^ 0x36u);
    opad[i] = static_cast<std::uint8_t>(k0[i] ^ 0x5cu);
  }

  // inner = SHA256((k0 xor ipad) || msg)
  std::string inner_input;
  inner_input.reserve(SHA256_BLOCK_BYTES + msg_len);
  inner_input.append(reinterpret_cast<const char*>(ipad.data()), ipad.size());
  inner_input.append(reinterpret_cast<const char*>(msg), msg_len);

  const auto inner = SHA256{inner_input}.digest();

  // outer = SHA256((k0 xor opad) || inner)
  std::string outer_input;
  outer_input.reserve(SHA256_BLOCK_BYTES + inner.size());
  outer_input.append(reinterpret_cast<const char*>(opad.data()), opad.size());
  outer_input.append(reinterpret_cast<const char*>(inner.data()), inner.size());

  const auto outer = SHA256{outer_input}.digest();
  return outer;
}

std::string to_hex(const std::array<std::uint8_t, 32>& d) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (auto b : d) {
    oss << std::setw(2) << static_cast<unsigned>(b);
  }
  return oss.str();
}

} // namespace

HMAC_SHA256::HMAC_SHA256(std::string_view key, std::string_view message)
    : digest_{hmac_sha256(key, reinterpret_cast<const std::uint8_t*>(message.data()), message.size())} {}

HMAC_SHA256::HMAC_SHA256(std::string_view key, std::istream& message) {
  auto bytes = read_all(message);
  digest_ = hmac_sha256(key, bytes.data(), bytes.size());
}

std::array<std::uint8_t, 32> HMAC_SHA256::digest() const {
  return digest_;
}

std::string HMAC_SHA256::hex_digest() const {
  return to_hex(digest_);
}

} // namespace hashlib


