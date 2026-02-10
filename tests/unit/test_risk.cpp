#include "guard/RiskScorer.h"
#include <cassert>

using namespace guard;

void test_risk() {
  RiskConfig cfg{};
  cfg.threshold_suspect = 1.0;
  cfg.threshold_block = 2.0;
  RiskScorer r(cfg);
  RiskFeatures f{};
  f.invalid_ratio = 2.0;
  auto d = r.score(f);
  assert(d.verdict == Verdict::Greylist || d.verdict == Verdict::Drop);
}
