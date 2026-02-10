#pragma once
#include <cstdint>
#include <optional>
#include <vector>
#include <array>
#include "Common.h"
#include "Util.h"

namespace guard {

enum class LimitReason : uint8_t {
  None = 0,
  Pps,
  Bps,
  MsgType,
  InvalidRatio,
  ReconnectChurn,
  TokenFail,
  ParseCost,
  QueuePressure,
};

struct LimitResult {
  bool allowed{true};
  LimitReason reason{LimitReason::None};
};

struct RateLimitDim {
  double rate_per_sec{0.0};
  double burst{0.0};
};

struct RateLimiterConfig {
  RateLimitDim pps{};
  RateLimitDim bps{};
  std::array<RateLimitDim, 16> msg_type_limits{}; // msg_type % 16
  double invalid_ratio_threshold{0.5};
  double reconnect_churn_threshold{0.5};
  double token_fail_threshold{0.5};
  double parse_cost_threshold{1.0};
  double queue_pressure_threshold{1.0};
  size_t table_size{4096};
  size_t msg_table_size{2048};
  uint64_t entry_ttl_ms{60000};
};

struct RateKey {
  uint64_t hash{0};
};

class RateLimiter {
 public:
  explicit RateLimiter(const RateLimiterConfig& cfg);

  LimitResult check_and_update(const RateKey& key, const IngressContext& ctx,
                               double msg_cost, double invalid_ratio,
                               double reconnect_churn, double token_fail_rate,
                               double parse_cost, double queue_pressure,
                               uint8_t msg_type);

 private:
  struct Entry {
    RateKey key{};
    double tokens_pps{0.0};
    double tokens_bps{0.0};
    TimeMs last_ms{0};
    EWMA invalid_ratio{};
    EWMA reconnect_churn{};
    EWMA token_fail_rate{};
    EWMA parse_cost{};
    EWMA queue_pressure{};
    bool occupied{false};
  };

  Entry* find_entry(std::vector<Entry>& table, const RateKey& key, TimeMs now_ms,
                    const RateLimitDim& dim_pps, const RateLimitDim& dim_bps);

  RateLimiterConfig cfg_{};
  std::vector<Entry> table_;
  std::vector<Entry> msg_table_;
};

} // namespace guard
