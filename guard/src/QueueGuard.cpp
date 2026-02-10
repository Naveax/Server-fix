#include "guard/QueueGuard.h"
#include <algorithm>

namespace guard {

QueueGuard::QueueGuard(const QueueGuardConfig& cfg) : cfg_(cfg) {
  clients_.resize(cfg_.client_table_size);
}

bool QueueGuard::allow_inbound(uint32_t inbound_depth, MsgPriority pri) const {
  if (inbound_depth >= cfg_.inbound_max) {
    return pri == MsgPriority::Critical || pri == MsgPriority::High;
  }
  return true;
}

bool QueueGuard::allow_outbound(uint32_t outbound_depth, MsgPriority pri) const {
  if (outbound_depth >= cfg_.outbound_max) {
    return pri == MsgPriority::Critical;
  }
  return true;
}

QueueGuard::ClientEntry* QueueGuard::find_client(uint64_t hash, TimeMs now_ms) {
  if (clients_.empty()) return nullptr;
  size_t idx = hash % clients_.size();
  for (size_t i = 0; i < clients_.size(); ++i) {
    ClientEntry& e = clients_[(idx + i) % clients_.size()];
    bool expired = e.occupied && (now_ms - e.last_ms) > cfg_.client_entry_ttl_ms;
    bool match = e.occupied && e.hash == hash && !expired;
    if (!e.occupied || match || expired) {
      if (!match) {
        e.hash = hash;
        e.tokens = cfg_.per_client_burst_bytes;
        e.last_ms = now_ms; // init/reset only on new/expired
      }
      e.occupied = true;
      return &e;
    }
  }
  return nullptr;
}

bool QueueGuard::allow_outbound_client(uint64_t client_hash, uint32_t bytes, MsgPriority pri, TimeMs now_ms) {
  if (pri == MsgPriority::Critical) return true;
  ClientEntry* e = find_client(client_hash, now_ms);
  if (!e) return true; // fail-open
  double elapsed = (now_ms > e->last_ms) ? (now_ms - e->last_ms) / 1000.0 : 0.0;
  e->tokens = std::min<double>(cfg_.per_client_burst_bytes,
                               e->tokens + elapsed * cfg_.per_client_out_bytes_per_sec);
  e->last_ms = now_ms;
  if (e->tokens < bytes) return false;
  e->tokens -= bytes;
  return true;
}

void QueueGuard::on_tick_end(uint32_t tick_ms, uint32_t inbound_depth, uint32_t outbound_depth) {
  state_.inbound_depth = inbound_depth;
  state_.outbound_depth = outbound_depth;
  state_.safe_mode = (tick_ms >= cfg_.safe_mode_tick_ms) ||
                     (inbound_depth >= cfg_.safe_mode_queue) ||
                     (outbound_depth >= cfg_.safe_mode_queue);
}

} // namespace guard
