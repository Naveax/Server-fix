#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include "guard/crypto/sha256.h"
#include "Common.h"

namespace guard {

uint64_t fnv1a64(const uint8_t* data, size_t len);

inline uint64_t hash_u64(uint64_t v) {
  return fnv1a64(reinterpret_cast<const uint8_t*>(&v), sizeof(v));
}

uint64_t hash_endpoint(const Endpoint& ep);
uint64_t hash_flow(const Endpoint& src, const Endpoint& dst, uint16_t proto_ver);

struct EWMA {
  double value{0.0};
  double alpha{0.1};
  void add(double sample) { value = alpha * sample + (1.0 - alpha) * value; }
};

std::array<uint8_t, 8> ip_prefix_hash(const uint8_t* ip, bool is_ipv6);

} // namespace guard
