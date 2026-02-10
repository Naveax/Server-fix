#include "guard/Amplification.h"

namespace guard {

AmplificationTracker::AmplificationTracker(const AmplificationConfig& cfg) : cfg_(cfg) {
  table_.resize(cfg_.table_size);
}

void AmplificationTracker::on_ingress(const AmplificationKey& key, ByteCount bytes, TimeMs now_ms) {
  if (table_.empty()) return;
  size_t idx = key.hash % table_.size();
  for (size_t i = 0; i < table_.size(); ++i) {
    Entry& e = table_[(idx + i) % table_.size()];
    bool expired = e.occupied && (now_ms - e.last_seen) > cfg_.entry_ttl_ms;
    bool match = e.occupied && e.key.hash == key.hash && !expired;
    if (!e.occupied || match || expired) {
      if (!match) {
        e.key = key;
        e.ingress = 0;
        e.egress = 0;
      }
      e.ingress += bytes;
      e.last_seen = now_ms;
      e.occupied = true;
      return;
    }
  }
}

bool AmplificationTracker::allow_egress(const AmplificationKey& key, ByteCount bytes, bool validated, TimeMs now_ms) {
  if (validated) return true;
  if (table_.empty()) return false;
  size_t idx = key.hash % table_.size();
  for (size_t i = 0; i < table_.size(); ++i) {
    Entry& e = table_[(idx + i) % table_.size()];
    bool expired = e.occupied && (now_ms - e.last_seen) > cfg_.entry_ttl_ms;
    bool match = e.occupied && e.key.hash == key.hash && !expired;
    if (!e.occupied || match || expired) {
      if (!match) {
        e.key = key;
        e.ingress = 0;
        e.egress = 0;
      }
      e.last_seen = now_ms;
      ByteCount max_egress = static_cast<ByteCount>(cfg_.max_ratio * static_cast<double>(e.ingress));
      if (e.egress + bytes <= max_egress) {
        e.egress += bytes;
        e.occupied = true;
        return true;
      }
      e.occupied = true;
      return false;
    }
  }
  return false;
}

} // namespace guard
