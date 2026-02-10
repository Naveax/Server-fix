#pragma once
#include <cstdint>
#include <vector>
#include "Common.h"

namespace guard {

// QUIC anti-amplification reference: enforce <= 3x egress before validation (RFC 9000).
struct AmplificationConfig {
  double max_ratio{3.0};
  uint64_t entry_ttl_ms{60000};
  size_t table_size{4096};
};

struct AmplificationKey {
  uint64_t hash{0};
};

class AmplificationTracker {
 public:
  explicit AmplificationTracker(const AmplificationConfig& cfg);
  void on_ingress(const AmplificationKey& key, ByteCount bytes, TimeMs now_ms);
  bool allow_egress(const AmplificationKey& key, ByteCount bytes, bool validated, TimeMs now_ms);

 private:
  struct Entry {
    AmplificationKey key{};
    ByteCount ingress{0};
    ByteCount egress{0};
    TimeMs last_seen{0};
    bool occupied{false};
  };
  AmplificationConfig cfg_{};
  std::vector<Entry> table_;
};

} // namespace guard
