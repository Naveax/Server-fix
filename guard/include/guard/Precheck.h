#pragma once
#include <cstdint>
#include "Common.h"

namespace guard {

// UDP usage guidance: limit sizes and rate (RFC 8085).
struct PrecheckConfig {
  uint16_t min_len{4};
  uint16_t max_len{1400};
  uint16_t min_proto{1};
  uint16_t max_proto{1};
};

struct PrecheckResult {
  bool ok{false};
  DropReason reason{DropReason::InvalidPrecheck};
};

PrecheckResult basic_precheck(const PacketView& pkt, uint16_t proto_ver, const PrecheckConfig& cfg);

} // namespace guard
