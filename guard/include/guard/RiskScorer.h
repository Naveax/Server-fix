#pragma once
#include <cstdint>
#include "Common.h"
#include "Util.h"

namespace guard {

struct RiskConfig {
  double w_invalid{1.0};
  double w_queue{1.0};
  double w_churn{0.8};
  double w_token_fail{0.6};
  double w_rate{0.8};
  double threshold_suspect{1.0};
  double threshold_block{2.0};
  double decay_alpha{0.1};
};

struct RiskFeatures {
  double invalid_ratio{0.0};
  double queue_pressure{0.0};
  double churn{0.0};
  double token_fail_rate{0.0};
  double rate_pressure{0.0};
};

struct RiskDecision {
  Verdict verdict{Verdict::Allow};
  uint32_t score{0};
};

class RiskScorer {
 public:
  explicit RiskScorer(const RiskConfig& cfg);
  RiskDecision score(const RiskFeatures& f);

 private:
  RiskConfig cfg_{};
  EWMA ewma_{};
};

} // namespace guard
