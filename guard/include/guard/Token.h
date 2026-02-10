#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace guard {

struct TokenFields {
  uint32_t pop_id{0};
  uint32_t server_id{0};
  uint16_t proto_ver{0};
  uint32_t time_bucket{0};
  std::array<uint8_t, 8> ip_prefix_hash{};
  uint16_t flags{0};
  uint8_t key_id{0};
};

struct TokenKey {
  std::array<uint8_t, 32> secret{};
  uint8_t key_id{0};
};

struct TokenKeyring {
  TokenKey current{};
  TokenKey previous{};
  uint32_t bucket_ms{1000};
  uint32_t max_skew_buckets{1};
};

struct TokenConfig {
  uint32_t bucket_ms{1000};
  uint32_t max_skew_buckets{1};
};

struct TokenResult {
  bool ok{false};
  TokenFields fields{};
};

// Stateless address validation token (Retry-like), see RFC 9000 and DTLS cookie precedent (RFC 9147).
// For production, prefer vetted crypto libraries and managed key rotation.
std::vector<uint8_t> token_mint(const TokenFields& fields, const TokenKey& key);
TokenResult token_verify(const std::vector<uint8_t>& token, const TokenKeyring& keys,
                         uint32_t now_bucket);
TokenResult token_verify(const uint8_t* data, size_t len, const TokenKeyring& keys,
                         uint32_t now_bucket);

} // namespace guard
