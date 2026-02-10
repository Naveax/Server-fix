#include "guard/QueueGuard.h"
#include <cassert>

using namespace guard;

void test_queue_guard() {
  QueueGuardConfig cfg{};
  cfg.inbound_max = 10;
  cfg.outbound_max = 10;
  QueueGuard q(cfg);
  assert(q.allow_inbound(5, MsgPriority::Normal));
  assert(!q.allow_inbound(10, MsgPriority::Low));
  assert(q.allow_inbound(10, MsgPriority::Critical));

  bool ok = q.allow_outbound_client(42, 1000000, MsgPriority::Low, 0);
  assert(!ok);
}
