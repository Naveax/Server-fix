#include "guard/Amplification.h"
#include <cassert>

using namespace guard;

void test_amplification() {
  AmplificationConfig cfg{};
  cfg.max_ratio = 3.0;
  cfg.table_size = 16;
  AmplificationTracker t(cfg);
  AmplificationKey k{42};
  t.on_ingress(k, 10, 0);
  assert(t.allow_egress(k, 30, false, 1));
  assert(!t.allow_egress(k, 1, false, 1));
  assert(t.allow_egress(k, 100, true, 1));
}
