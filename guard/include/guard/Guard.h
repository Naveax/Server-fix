#pragma once
#include "Common.h"
#include "Metrics.h"
#include "Token.h"
#include "Amplification.h"
#include "RateLimiter.h"
#include "ParserBudget.h"
#include "Precheck.h"
#include "QueueGuard.h"
#include "RiskScorer.h"
#include "Enforcement.h"
#include "Util.h"
#ifdef GUARD_ENABLE_SANDBOX
#include "SandboxClient.h"
#endif

namespace guard {

struct GuardConfig {
  PrecheckConfig precheck{};
  AmplificationConfig amplification{};
  RateLimiterConfig pre_auth_limits{};
  RateLimiterConfig post_auth_limits{};
  ParserBudgetConfig parser_budget{};
  QueueGuardConfig queue{};
  RiskConfig risk{};
  TokenKeyring token_keys{};
#ifdef GUARD_ENABLE_SANDBOX
  SandboxConfig sandbox{};
#endif
};

class Guard {
 public:
  explicit Guard(const GuardConfig& cfg, IMetricSink* metrics = nullptr, IEnforcementHook* hook = nullptr);

  Decision on_packet_receive(const PacketView& pkt, const IngressContext& ctx);
  Decision on_packet_send(ByteCount bytes, const EgressContext& ctx);
  void on_tick_end(uint32_t tick_ms, uint32_t in_depth, uint32_t out_depth);

 private:
  GuardConfig cfg_{};
  NoopMetricSink noop_{};
  IMetricSink* metrics_{nullptr};
  NoopEnforcementHook noop_hook_{};
  IEnforcementHook* hook_{nullptr};
  AmplificationTracker amp_;
  RateLimiter pre_auth_;
  RateLimiter post_auth_;
  QueueGuard queue_;
  RiskScorer risk_;
#ifdef GUARD_ENABLE_SANDBOX
  SandboxClient sandbox_;
#endif
};

} // namespace guard
