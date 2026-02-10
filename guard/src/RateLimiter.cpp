#include "guard/RateLimiter.h"
#include <algorithm>

namespace guard {

RateLimiter::RateLimiter(const RateLimiterConfig& cfg) : cfg_(cfg) {
  table_.resize(cfg_.table_size);
  msg_table_.resize(cfg_.msg_table_size);
}

RateLimiter::Entry* RateLimiter::find_entry(std::vector<Entry>& table, const RateKey& key, TimeMs now_ms,
                                            const RateLimitDim& dim_pps, const RateLimitDim& dim_bps) {
  if (table.empty()) return nullptr;
  size_t idx = key.hash % table.size();
  for (size_t i = 0; i < table.size(); ++i) {
    Entry& e = table[(idx + i) % table.size()];
    bool expired = e.occupied && (now_ms - e.last_ms) > cfg_.entry_ttl_ms;
    bool match = e.occupied && e.key.hash == key.hash && !expired;
    if (!e.occupied || match || expired) {
      if (!match) {
        e.key = key;
        e.tokens_pps = dim_pps.burst;
        e.tokens_bps = dim_bps.burst;
        e.invalid_ratio.value = 0.0;
        e.reconnect_churn.value = 0.0;
        e.token_fail_rate.value = 0.0;
        e.parse_cost.value = 0.0;
        e.queue_pressure.value = 0.0;
        e.last_ms = now_ms; // init/reset timebase only on new/expired
      }
      e.occupied = true;
      return &e;
    }
  }
  return nullptr;
}

LimitResult RateLimiter::check_and_update(const RateKey& key, const IngressContext& ctx,
                                         double msg_cost, double invalid_ratio,
                                         double reconnect_churn, double token_fail_rate,
                                         double parse_cost, double queue_pressure,
                                         uint8_t msg_type) {
  LimitResult res{};
  Entry* e = find_entry(table_, key, ctx.now_ms, cfg_.pps, cfg_.bps);
  if (!e) return res; // fail-open on table exhaustion

  double elapsed = (ctx.now_ms > e->last_ms) ? (ctx.now_ms - e->last_ms) / 1000.0 : 0.0;
  e->tokens_pps = std::min(cfg_.pps.burst, e->tokens_pps + elapsed * cfg_.pps.rate_per_sec);
  e->tokens_bps = std::min(cfg_.bps.burst, e->tokens_bps + elapsed * cfg_.bps.rate_per_sec);
  e->last_ms = ctx.now_ms; // advance timebase after refill

  e->invalid_ratio.add(invalid_ratio);
  e->reconnect_churn.add(reconnect_churn);
  e->token_fail_rate.add(token_fail_rate);
  e->parse_cost.add(parse_cost);
  e->queue_pressure.add(queue_pressure);

  if (cfg_.pps.rate_per_sec > 0.0 && e->tokens_pps < 1.0) { res.allowed = false; res.reason = LimitReason::Pps; return res; }
  if (cfg_.bps.rate_per_sec > 0.0 && e->tokens_bps < msg_cost) { res.allowed = false; res.reason = LimitReason::Bps; return res; }

  if (e->invalid_ratio.value > cfg_.invalid_ratio_threshold) { res.allowed = false; res.reason = LimitReason::InvalidRatio; return res; }
  if (e->reconnect_churn.value > cfg_.reconnect_churn_threshold) { res.allowed = false; res.reason = LimitReason::ReconnectChurn; return res; }
  if (e->token_fail_rate.value > cfg_.token_fail_threshold) { res.allowed = false; res.reason = LimitReason::TokenFail; return res; }
  if (e->parse_cost.value > cfg_.parse_cost_threshold) { res.allowed = false; res.reason = LimitReason::ParseCost; return res; }
  if (e->queue_pressure.value > cfg_.queue_pressure_threshold) { res.allowed = false; res.reason = LimitReason::QueuePressure; return res; }

  // Per-msg-type budget (optional)
  size_t slot = msg_type % cfg_.msg_type_limits.size();
  const auto& md = cfg_.msg_type_limits[slot];
  if (md.rate_per_sec > 0.0 || md.burst > 0.0) {
    RateKey mkey{key.hash ^ (static_cast<uint64_t>(msg_type) * 0x9e3779b97f4a7c15ULL)};
    Entry* me = find_entry(msg_table_, mkey, ctx.now_ms, md, md);
    if (me) {
      double me_elapsed = (ctx.now_ms > me->last_ms) ? (ctx.now_ms - me->last_ms) / 1000.0 : 0.0;
      me->tokens_pps = std::min(md.burst, me->tokens_pps + me_elapsed * md.rate_per_sec);
      me->last_ms = ctx.now_ms;
      if (me->tokens_pps < 1.0) { res.allowed = false; res.reason = LimitReason::MsgType; return res; }
      me->tokens_pps -= 1.0;
    }
  }

  if (cfg_.pps.rate_per_sec > 0.0) e->tokens_pps -= 1.0;
  if (cfg_.bps.rate_per_sec > 0.0) e->tokens_bps -= msg_cost;
  return res;
}

} // namespace guard
