#include "guard/Guard.h"
#include <algorithm>
#include <array>

namespace guard {

namespace {
uint64_t hash_ip_only(const Endpoint& ep) {
  return fnv1a64(ep.ip.data(), ep.is_ipv6 ? 16 : 4);
}
uint64_t hash_ip_prefix(const Endpoint& ep) {
  auto pref = ip_prefix_hash(ep.ip.data(), ep.is_ipv6);
  return fnv1a64(pref.data(), pref.size());
}
}

Guard::Guard(const GuardConfig& cfg, IMetricSink* metrics, IEnforcementHook* hook)
    : cfg_(cfg),
      metrics_(metrics ? metrics : &noop_),
      hook_(hook ? hook : &noop_hook_),
      amp_(cfg.amplification),
      pre_auth_(cfg.pre_auth_limits),
      post_auth_(cfg.post_auth_limits),
      queue_(cfg.queue),
      risk_(cfg.risk)
#ifdef GUARD_ENABLE_SANDBOX
      , sandbox_(cfg.sandbox, metrics_)
#endif
{
}

Decision Guard::on_packet_receive(const PacketView& pkt, const IngressContext& ctx) {
  auto pre = basic_precheck(pkt, ctx.proto_ver, cfg_.precheck);
  if (!pre.ok) {
    metrics_->inc_counter("guard_inbound_drop_total", 1, { {"reason","precheck"} });
    hook_->on_enforcement(ctx, Verdict::Drop, pre.reason, 0);
    return Decision::Drop(pre.reason);
  }

  bool token_ok = ctx.validated;
  if (!ctx.validated && ctx.token.data && ctx.token.len > 0) {
    auto res = token_verify(ctx.token.data, ctx.token.len, cfg_.token_keys,
                            static_cast<uint32_t>(ctx.now_ms / cfg_.token_keys.bucket_ms));
    if (res.ok) {
      auto expected = ip_prefix_hash(ctx.src.ip.data(), ctx.src.is_ipv6);
      token_ok = (res.fields.pop_id == ctx.pop_id) &&
                 (res.fields.server_id == ctx.server_id) &&
                 (res.fields.proto_ver == ctx.proto_ver) &&
                 (res.fields.ip_prefix_hash == expected);
    }
  }

  bool validated = ctx.validated || token_ok;

  // Anti-amplification ingress accounting for unvalidated sources (RFC 9000).
  AmplificationKey flow_key{hash_flow(ctx.src, ctx.dst, ctx.proto_ver)};
  if (!validated) {
    amp_.on_ingress(flow_key, ctx.ingress_bytes ? ctx.ingress_bytes : pkt.len, ctx.now_ms);
  }

  double token_fail_rate = ctx.token_fail_rate > 0.0 ? ctx.token_fail_rate : (token_ok ? 0.0 : 1.0);
  if (!token_ok && !ctx.validated) {
    metrics_->inc_counter("guard_token_fail_total", 1);
  }

#ifdef GUARD_ENABLE_SANDBOX
  auto sb = sandbox_.decode_packet(pkt);
  if (sb == SandboxStatus::Timeout) {
    metrics_->inc_counter("guard_inbound_drop_total", 1, { {"reason","sandbox_timeout"} });
    return Decision::Drop(DropReason::SandboxTimeout);
  }
  if (sb == SandboxStatus::Crash) {
    metrics_->inc_counter("guard_inbound_drop_total", 1, { {"reason","sandbox_crash"} });
    return Decision::Drop(DropReason::SandboxCrash);
  }
  if (sb == SandboxStatus::Invalid) {
    metrics_->inc_counter("guard_invalid_parse_total", 1);
    return Decision::Drop(DropReason::ParserBudget);
  }
  if (sb == SandboxStatus::WouldBlock) {
    metrics_->inc_counter("guard_inbound_drop_total", 1, { {"reason","sandbox_backpressure"} });
    return Decision::Drop(DropReason::QueueOverload);
  }
#endif

  // Queue guard (drop/degrade noncritical under pressure).
  uint32_t in_depth = ctx.inbound_depth > 0 ? ctx.inbound_depth
                                            : static_cast<uint32_t>(ctx.queue_pressure * cfg_.queue.inbound_max);
  if (!queue_.allow_inbound(in_depth, static_cast<MsgPriority>(ctx.priority))) {
    metrics_->inc_counter("guard_inbound_drop_total", 1, { {"reason","queue"} });
    hook_->on_enforcement(ctx, Verdict::Drop, DropReason::QueueOverload, 0);
    return Decision::Drop(DropReason::QueueOverload);
  }

  // Rate limiting across multiple keys.
  RateLimiter& rl = validated ? post_auth_ : pre_auth_;
  double msg_cost = ctx.msg_cost > 0.0 ? ctx.msg_cost : static_cast<double>(pkt.len);

  std::array<RateKey, 6> keys{};
  size_t key_count = 0;
  keys[key_count++] = RateKey{hash_ip_only(ctx.src) ^ 0x01};
  keys[key_count++] = RateKey{hash_ip_prefix(ctx.src) ^ 0x02};
  if (ctx.asn.has_value()) keys[key_count++] = RateKey{hash_u64(ctx.asn.value()) ^ 0x03};
  if (ctx.account_id.has_value()) keys[key_count++] = RateKey{hash_u64(ctx.account_id.value()) ^ 0x04};
  if (ctx.session_id.has_value()) keys[key_count++] = RateKey{hash_u64(ctx.session_id.value()) ^ 0x05};
  keys[key_count++] = RateKey{hash_u64(ctx.pop_id) ^ 0x06};

  for (size_t i = 0; i < key_count; ++i) {
    const auto& k = keys[i];
    auto lim = rl.check_and_update(k, ctx, msg_cost,
                                   ctx.invalid_ratio,
                                   ctx.reconnect_churn,
                                   token_fail_rate,
                                   ctx.parse_cost,
                                   ctx.queue_pressure,
                                   ctx.msg_type);
    if (!lim.allowed) {
      metrics_->inc_counter("guard_inbound_drop_total", 1, { {"reason","rate_limit"} });
      hook_->on_enforcement(ctx, Verdict::Drop, DropReason::RateLimit, 0);
      return Decision::Drop(DropReason::RateLimit);
    }
  }

  // Risk scoring (deterministic-first)
  RiskFeatures rf{};
  rf.invalid_ratio = ctx.invalid_ratio;
  rf.queue_pressure = ctx.queue_pressure;
  rf.churn = ctx.reconnect_churn;
  rf.token_fail_rate = token_fail_rate;
  rf.rate_pressure = 0.0;
  auto rd = risk_.score(rf);
  metrics_->observe_histogram("guard_risk_score_histogram", static_cast<double>(rd.score));
  if (rd.verdict == Verdict::Greylist) {
    metrics_->inc_counter("guard_greylist_total", 1);
    hook_->on_enforcement(ctx, Verdict::Greylist, DropReason::Risk, rd.score);
    return Decision::Grey(DropReason::Risk, rd.score);
  }
  if (rd.verdict == Verdict::Drop) {
    metrics_->inc_counter("guard_inbound_drop_total", 1, { {"reason","risk"} });
    hook_->on_enforcement(ctx, Verdict::Drop, DropReason::Risk, rd.score);
    return Decision::Drop(DropReason::Risk);
  }

  return Decision::Allow();
}

Decision Guard::on_packet_send(ByteCount bytes, const EgressContext& ctx) {
  AmplificationKey flow_key{hash_flow(ctx.src, ctx.dst, ctx.proto_ver)};
  if (!amp_.allow_egress(flow_key, bytes, ctx.validated, ctx.now_ms)) {
    metrics_->inc_counter("guard_outbound_drop_total", 1, { {"reason","amplification"} });
    metrics_->inc_counter("guard_amplification_budget_exceeded_total", 1);
    return Decision::Drop(DropReason::Amplification);
  }
  if (!queue_.allow_outbound(ctx.outbound_depth, static_cast<MsgPriority>(ctx.priority))) {
    metrics_->inc_counter("guard_outbound_drop_total", 1, { {"reason","queue"} });
    return Decision::Drop(DropReason::QueueOverload);
  }
  uint64_t client_hash = ctx.has_client_key ? ctx.client_key :
                         (ctx.account_id.has_value() ? ctx.account_id.value() :
                          (ctx.session_id.has_value() ? ctx.session_id.value() : hash_ip_only(ctx.dst)));
  if (!queue_.allow_outbound_client(client_hash, static_cast<uint32_t>(bytes),
                                    static_cast<MsgPriority>(ctx.priority), ctx.now_ms)) {
    metrics_->inc_counter("guard_outbound_drop_total", 1, { {"reason","per_client"} });
    return Decision::Drop(DropReason::QueueOverload);
  }
  return Decision::Allow();
}

void Guard::on_tick_end(uint32_t tick_ms, uint32_t in_depth, uint32_t out_depth) {
  queue_.on_tick_end(tick_ms, in_depth, out_depth);
  metrics_->set_gauge("guard_queue_in_depth", in_depth);
  metrics_->set_gauge("guard_queue_out_depth", out_depth);
  metrics_->set_gauge("guard_safe_mode_active", queue_.safe_mode() ? 1.0 : 0.0);
}

} // namespace guard
