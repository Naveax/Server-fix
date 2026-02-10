#pragma once
#include <cstdint>
#include <vector>
#include "Common.h"
#include "Util.h"

namespace guard {

enum class MsgPriority : uint8_t {
  Critical = 0,
  High = 1,
  Normal = 2,
  Low = 3,
};

struct QueueGuardConfig {
  uint32_t inbound_max{1024};
  uint32_t outbound_max{1024};
  uint32_t safe_mode_tick_ms{50};
  uint32_t safe_mode_queue{800};
  uint32_t per_client_out_bytes_per_sec{50000};
  uint32_t per_client_burst_bytes{100000};
  size_t client_table_size{2048};
  uint64_t client_entry_ttl_ms{60000};
};

struct QueueState {
  uint32_t inbound_depth{0};
  uint32_t outbound_depth{0};
  bool safe_mode{false};
};

class QueueGuard {
 public:
  explicit QueueGuard(const QueueGuardConfig& cfg);

  bool allow_inbound(uint32_t inbound_depth, MsgPriority pri) const;
  bool allow_outbound(uint32_t outbound_depth, MsgPriority pri) const;
  bool allow_outbound_client(uint64_t client_hash, uint32_t bytes, MsgPriority pri, TimeMs now_ms);
  void on_tick_end(uint32_t tick_ms, uint32_t inbound_depth, uint32_t outbound_depth);
  bool safe_mode() const { return state_.safe_mode; }

 private:
  struct ClientEntry {
    uint64_t hash{0};
    double tokens{0.0};
    TimeMs last_ms{0};
    bool occupied{false};
  };

  ClientEntry* find_client(uint64_t hash, TimeMs now_ms);

  QueueGuardConfig cfg_{};
  QueueState state_{};
  std::vector<ClientEntry> clients_;
};

} // namespace guard
