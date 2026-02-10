#pragma once
#include "Common.h"

namespace guard {

class IEnforcementHook {
 public:
  virtual ~IEnforcementHook() = default;
  virtual void on_enforcement(const IngressContext& ctx, Verdict v, DropReason r, uint32_t score) = 0;
};

class NoopEnforcementHook : public IEnforcementHook {
 public:
  void on_enforcement(const IngressContext&, Verdict, DropReason, uint32_t) override {}
};

} // namespace guard
