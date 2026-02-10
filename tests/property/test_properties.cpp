#include "guard/RateLimiter.h"
#include <cassert>

using namespace guard;

int main() {
  RateLimiterConfig cfg{};
  cfg.pps.rate_per_sec = 100.0;
  cfg.pps.burst = 10.0;
  cfg.bps.rate_per_sec = 10000.0;
  cfg.bps.burst = 1000.0;
  cfg.table_size = 64;
  RateLimiter rl(cfg);

  IngressContext ctx{};
  ctx.now_ms = 0;
  RateKey k{123};

  for (int i = 0; i < 100; ++i) {
    ctx.now_ms += 1;
    auto r = rl.check_and_update(k, ctx, 50.0, 0, 0, 0, 0, 0, 0);
    if (!r.allowed) {
      // If rate limited, advancing time should eventually allow.
      ctx.now_ms += 1000;
      auto r2 = rl.check_and_update(k, ctx, 50.0, 0, 0, 0, 0, 0, 0);
      assert(r2.allowed);
      break;
    }
  }

  return 0;
}
