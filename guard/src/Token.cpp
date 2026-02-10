#include "guard/Token.h"
#include "guard/crypto/sha256.h"
#include <cstring>

namespace guard {

namespace {
constexpr uint8_t kTokenVersion = 1;
constexpr size_t kMacSize = 16;

static void write_u16(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}
static void write_u32(std::vector<uint8_t>& out, uint32_t v) {
  out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}
static uint16_t read_u16(const uint8_t* p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
static uint32_t read_u32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) |
         static_cast<uint32_t>(p[3]);
}

static std::array<uint8_t, 32> hmac_sha256(const uint8_t* key, size_t key_len,
                                           const uint8_t* msg, size_t msg_len) {
  constexpr size_t block = 64;
  std::array<uint8_t, block> k0{};
  if (key_len > block) {
    auto h = sha256(key, key_len);
    std::memcpy(k0.data(), h.data(), h.size());
  } else {
    std::memcpy(k0.data(), key, key_len);
  }

  std::array<uint8_t, block> o_key{};
  std::array<uint8_t, block> i_key{};
  for (size_t i = 0; i < block; ++i) {
    o_key[i] = static_cast<uint8_t>(k0[i] ^ 0x5c);
    i_key[i] = static_cast<uint8_t>(k0[i] ^ 0x36);
  }

  std::vector<uint8_t> inner;
  inner.reserve(block + msg_len);
  inner.insert(inner.end(), i_key.begin(), i_key.end());
  inner.insert(inner.end(), msg, msg + msg_len);
  auto inner_hash = sha256(inner.data(), inner.size());

  std::vector<uint8_t> outer;
  outer.reserve(block + inner_hash.size());
  outer.insert(outer.end(), o_key.begin(), o_key.end());
  outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
  return sha256(outer.data(), outer.size());
}

static bool constant_time_eq(const uint8_t* a, const uint8_t* b, size_t len) {
  uint8_t r = 0;
  for (size_t i = 0; i < len; ++i) r |= a[i] ^ b[i];
  return r == 0;
}

static std::vector<uint8_t> serialize_fields(const TokenFields& f) {
  std::vector<uint8_t> out;
  out.reserve(1 + 1 + 2 + 4 + 4 + 2 + 4 + 8);
  out.push_back(kTokenVersion);
  out.push_back(f.key_id);
  write_u16(out, f.flags);
  write_u32(out, f.pop_id);
  write_u32(out, f.server_id);
  write_u16(out, f.proto_ver);
  write_u32(out, f.time_bucket);
  out.insert(out.end(), f.ip_prefix_hash.begin(), f.ip_prefix_hash.end());
  return out;
}

} // namespace

std::vector<uint8_t> token_mint(const TokenFields& fields, const TokenKey& key) {
  TokenFields f = fields;
  f.key_id = key.key_id;
  std::vector<uint8_t> body = serialize_fields(f);
  auto mac = hmac_sha256(key.secret.data(), key.secret.size(), body.data(), body.size());
  body.insert(body.end(), mac.begin(), mac.begin() + kMacSize);
  return body;
}

TokenResult token_verify(const uint8_t* data, size_t len, const TokenKeyring& keys,
                         uint32_t now_bucket) {
  TokenResult res{};
  if (len < (1 + 1 + 2 + 4 + 4 + 2 + 4 + 8 + kMacSize)) return res;
  const uint8_t* p = data;
  if (p[0] != kTokenVersion) return res;
  TokenFields f{};
  f.key_id = p[1];
  f.flags = read_u16(p + 2);
  f.pop_id = read_u32(p + 4);
  f.server_id = read_u32(p + 8);
  f.proto_ver = read_u16(p + 12);
  f.time_bucket = read_u32(p + 14);
  std::memcpy(f.ip_prefix_hash.data(), p + 18, 8);

  const uint8_t* mac = p + 26;
  const size_t body_len = 26;

  const TokenKey* key = nullptr;
  if (f.key_id == keys.current.key_id) key = &keys.current;
  else if (f.key_id == keys.previous.key_id) key = &keys.previous;
  else return res;

  auto calc = hmac_sha256(key->secret.data(), key->secret.size(), data, body_len);
  if (!constant_time_eq(mac, calc.data(), kMacSize)) return res;

  uint32_t max_skew = keys.max_skew_buckets;
  if (f.time_bucket + max_skew < now_bucket || now_bucket + max_skew < f.time_bucket) {
    return res;
  }

  res.ok = true;
  res.fields = f;
  return res;
}

TokenResult token_verify(const std::vector<uint8_t>& token, const TokenKeyring& keys,
                         uint32_t now_bucket) {
  return token_verify(token.data(), token.size(), keys, now_bucket);
}

} // namespace guard
