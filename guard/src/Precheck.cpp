#include "guard/Precheck.h"

namespace guard {

PrecheckResult basic_precheck(const PacketView& pkt, uint16_t proto_ver, const PrecheckConfig& cfg) {
  PrecheckResult res{};
  if (pkt.len < cfg.min_len || pkt.len > cfg.max_len) {
    res.ok = false;
    res.reason = DropReason::InvalidPrecheck;
    return res;
  }
  if (proto_ver < cfg.min_proto || proto_ver > cfg.max_proto) {
    res.ok = false;
    res.reason = DropReason::InvalidPrecheck;
    return res;
  }
  res.ok = true;
  res.reason = DropReason::None;
  return res;
}

} // namespace guard
