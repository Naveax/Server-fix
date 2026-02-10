#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace guard {

using ByteCount = uint64_t;
using TimeMs = uint64_t;

struct Endpoint {
  bool is_ipv6{false};
  std::array<uint8_t, 16> ip{}; // IPv4 stored in first 4 bytes
  uint16_t port{0};
};

struct PacketView {
  const uint8_t* data{nullptr};
  size_t len{0};
};

struct TokenView {
  const uint8_t* data{nullptr};
  size_t len{0};
};

enum class Verdict : uint8_t {
  Allow = 0,
  Drop = 1,
  Greylist = 2,
};

enum class DropReason : uint16_t {
  None = 0,
  InvalidPrecheck,
  TokenFail,
  Amplification,
  RateLimit,
  Risk,
  QueueOverload,
  ParserBudget,
  SandboxTimeout,
  SandboxCrash,
  InternalError,
};

struct Decision {
  Verdict verdict{Verdict::Allow};
  DropReason reason{DropReason::None};
  uint32_t risk_score{0};

  static Decision Allow() { return {}; }
  static Decision Drop(DropReason r) { return {Verdict::Drop, r, 0}; }
  static Decision Grey(DropReason r, uint32_t score) { return {Verdict::Greylist, r, score}; }
};

struct IngressContext {
  TimeMs now_ms{0};
  Endpoint src{};
  Endpoint dst{};
  bool validated{false};
  uint32_t pop_id{0};
  uint32_t server_id{0};
  uint16_t proto_ver{0};
  std::optional<uint64_t> account_id{};
  std::optional<uint64_t> session_id{};
  std::optional<uint32_t> asn{};
  uint8_t msg_type{0};
  uint8_t priority{2}; // MsgPriority::Normal
  ByteCount ingress_bytes{0};
  uint32_t inbound_depth{0};
  TokenView token{};

  // Optional caller-provided signals (default 0)
  double invalid_ratio{0.0};
  double reconnect_churn{0.0};
  double token_fail_rate{0.0};
  double parse_cost{0.0};
  double queue_pressure{0.0};
  double msg_cost{0.0};
};

struct EgressContext {
  TimeMs now_ms{0};
  Endpoint src{};
  Endpoint dst{};
  bool validated{false};
  uint32_t pop_id{0};
  uint32_t server_id{0};
  uint16_t proto_ver{0};
  std::optional<uint64_t> account_id{};
  std::optional<uint64_t> session_id{};
  std::optional<uint32_t> asn{};
  uint8_t msg_type{0};
  uint8_t priority{2}; // MsgPriority::Normal
  ByteCount egress_bytes{0};
  uint32_t outbound_depth{0};
  bool has_client_key{false};
  uint64_t client_key{0};
};

} // namespace guard
