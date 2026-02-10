#include "guard/RiskScorer.h"

namespace guard {

RiskScorer::RiskScorer(const RiskConfig& cfg) : cfg_(cfg) {
  ewma_.alpha = cfg_.decay_alpha;
}

RiskDecision RiskScorer::score(const RiskFeatures& f) {
  double raw = cfg_.w_invalid * f.invalid_ratio +
               cfg_.w_queue * f.queue_pressure +
               cfg_.w_churn * f.churn +
               cfg_.w_token_fail * f.token_fail_rate +
               cfg_.w_rate * f.rate_pressure;
  ewma_.add(raw);
  RiskDecision out{};
  out.score = static_cast<uint32_t>(ewma_.value * 100.0);
  if (ewma_.value >= cfg_.threshold_block) {
    out.verdict = Verdict::Drop;
  } else if (ewma_.value >= cfg_.threshold_suspect) {
    out.verdict = Verdict::Greylist;
  } else {
    out.verdict = Verdict::Allow;
  }
  return out;
}

} // namespace guard
