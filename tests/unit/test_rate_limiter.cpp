#include "guard/RateLimiter.h"
#include <cassert>

using namespace guard;

void test_rate_limiter() {
  RateLimiterConfig cfg{};
  cfg.pps.rate_per_sec = 10.0;
  cfg.pps.burst = 5.0;
  cfg.bps.rate_per_sec = 1000.0;
  cfg.bps.burst = 500.0;
  cfg.table_size = 16;
  RateLimiter rl(cfg);

  IngressContext ctx{};
  ctx.now_ms = 0;
  RateKey k{1};

  for (int i = 0; i < 5; ++i) {
    auto r = rl.check_and_update(k, ctx, 10.0, 0, 0, 0, 0, 0, 0);
    assert(r.allowed);
  }
  auto r = rl.check_and_update(k, ctx, 10.0, 0, 0, 0, 0, 0, 0);
  assert(!r.allowed);
}
