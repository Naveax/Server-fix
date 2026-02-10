#include "guard/Guard.h"
#include <cstddef>
#include <cstdint>

using namespace guard;

namespace {
uint8_t take_u8(const uint8_t* data, size_t size, size_t& pos, uint8_t fallback = 0) {
  if (pos >= size) return fallback;
  return data[pos++];
}

uint16_t take_u16(const uint8_t* data, size_t size, size_t& pos, uint16_t fallback = 0) {
  uint16_t hi = take_u8(data, size, pos, static_cast<uint8_t>(fallback >> 8));
  uint16_t lo = take_u8(data, size, pos, static_cast<uint8_t>(fallback & 0xFF));
  return static_cast<uint16_t>((hi << 8) | lo);
}

uint32_t take_u32(const uint8_t* data, size_t size, size_t& pos, uint32_t fallback = 0) {
  uint32_t b0 = take_u8(data, size, pos, static_cast<uint8_t>(fallback >> 24));
  uint32_t b1 = take_u8(data, size, pos, static_cast<uint8_t>(fallback >> 16));
  uint32_t b2 = take_u8(data, size, pos, static_cast<uint8_t>(fallback >> 8));
  uint32_t b3 = take_u8(data, size, pos, static_cast<uint8_t>(fallback));
  return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!data || size == 0) return 0;

  GuardConfig cfg{};
  cfg.precheck.min_len = 1;
  cfg.precheck.max_len = 1400;
  cfg.precheck.min_proto = 1;
  cfg.precheck.max_proto = 1;

  cfg.pre_auth_limits.pps.rate_per_sec = 1000.0;
  cfg.pre_auth_limits.pps.burst = 100.0;
  cfg.pre_auth_limits.bps.rate_per_sec = 200000.0;
  cfg.pre_auth_limits.bps.burst = 100000.0;
  cfg.pre_auth_limits.table_size = 128;
  cfg.pre_auth_limits.msg_table_size = 128;

  cfg.post_auth_limits = cfg.pre_auth_limits;

  cfg.queue.inbound_max = 128;
  cfg.queue.outbound_max = 128;
  cfg.queue.client_table_size = 64;
  cfg.queue.per_client_out_bytes_per_sec = 5000;
  cfg.queue.per_client_burst_bytes = 10000;

  cfg.token_keys.bucket_ms = 1000;
  cfg.token_keys.max_skew_buckets = 1;
  cfg.token_keys.current.key_id = 1;
  for (size_t i = 0; i < cfg.token_keys.current.secret.size(); ++i) {
    cfg.token_keys.current.secret[i] = static_cast<uint8_t>(i * 3 + 1);
  }
  cfg.token_keys.previous = cfg.token_keys.current;

#ifdef GUARD_ENABLE_SANDBOX
  cfg.sandbox.inprocess_fallback = true;
  cfg.sandbox.max_inflight = 2;
#endif

  Guard guard(cfg, nullptr, nullptr);

  size_t pos = 0;
  PacketView pkt{data, size};

  IngressContext ictx{};
  ictx.now_ms = 1000 + take_u32(data, size, pos, 0);
  ictx.proto_ver = 1;
  ictx.pop_id = take_u32(data, size, pos, 1);
  ictx.server_id = take_u32(data, size, pos, 1);

  ictx.src.is_ipv6 = (take_u8(data, size, pos, 0) & 1) != 0;
  for (size_t i = 0; i < (ictx.src.is_ipv6 ? 16 : 4); ++i) {
    ictx.src.ip[i] = take_u8(data, size, pos, static_cast<uint8_t>(i));
  }
  ictx.src.port = take_u16(data, size, pos, 10000);

  ictx.dst.is_ipv6 = ictx.src.is_ipv6;
  for (size_t i = 0; i < (ictx.dst.is_ipv6 ? 16 : 4); ++i) {
    ictx.dst.ip[i] = take_u8(data, size, pos, static_cast<uint8_t>(i + 1));
  }
  ictx.dst.port = take_u16(data, size, pos, 20000);

  ictx.msg_type = take_u8(data, size, pos, 0);
  ictx.priority = static_cast<uint8_t>(take_u8(data, size, pos, 2) % 4);
  ictx.msg_cost = 1.0 + (take_u8(data, size, pos, 0) % 64);

  ictx.inbound_depth = take_u8(data, size, pos, 0) % cfg.queue.inbound_max;
  ictx.queue_pressure = static_cast<double>(ictx.inbound_depth) / cfg.queue.inbound_max;

  // Optional token view from remaining input
  if (pos < size) {
    ictx.token.data = data + pos;
    ictx.token.len = (size - pos) > 64 ? 64 : (size - pos);
  }

  (void)guard.on_packet_receive(pkt, ictx);

  EgressContext ectx{};
  ectx.now_ms = ictx.now_ms + 1;
  ectx.src = ictx.dst;
  ectx.dst = ictx.src;
  ectx.validated = ictx.validated;
  ectx.pop_id = ictx.pop_id;
  ectx.server_id = ictx.server_id;
  ectx.proto_ver = ictx.proto_ver;
  ectx.msg_type = ictx.msg_type;
  ectx.priority = ictx.priority;
  ectx.outbound_depth = take_u8(data, size, pos, 0) % cfg.queue.outbound_max;
  ectx.egress_bytes = take_u16(data, size, pos, 32);

  (void)guard.on_packet_send(ectx.egress_bytes, ectx);

  return 0;
}
