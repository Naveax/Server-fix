#include "guard/Util.h"

namespace guard {

uint64_t fnv1a64(const uint8_t* data, size_t len) {
  const uint64_t fnv_offset = 1469598103934665603ull;
  const uint64_t fnv_prime = 1099511628211ull;
  uint64_t hash = fnv_offset;
  for (size_t i = 0; i < len; ++i) {
    hash ^= static_cast<uint64_t>(data[i]);
    hash *= fnv_prime;
  }
  return hash;
}

uint64_t hash_endpoint(const Endpoint& ep) {
  uint64_t h = fnv1a64(ep.ip.data(), ep.is_ipv6 ? 16 : 4);
  h ^= static_cast<uint64_t>(ep.port) * 0x9e3779b185ebca87ULL;
  return h;
}

uint64_t hash_flow(const Endpoint& src, const Endpoint& dst, uint16_t proto_ver) {
  uint64_t h1 = hash_endpoint(src);
  uint64_t h2 = hash_endpoint(dst);
  uint64_t h = h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
  h ^= static_cast<uint64_t>(proto_ver) * 0x517cc1b727220a95ULL;
  return h;
}

std::array<uint8_t, 8> ip_prefix_hash(const uint8_t* ip, bool is_ipv6) {
  size_t prefix_bytes = is_ipv6 ? 7 : 3; // /56 or /24
  auto digest = sha256(ip, prefix_bytes);
  std::array<uint8_t, 8> out{};
  for (size_t i = 0; i < 8; ++i) out[i] = digest[i];
  return out;
}

} // namespace guard
