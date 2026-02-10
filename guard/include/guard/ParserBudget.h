#pragma once
#include <cstdint>

namespace guard {

struct ParserBudgetConfig {
  uint32_t max_depth{4};
  uint32_t max_fields{64};
  uint32_t max_varint_bytes{5};
  uint32_t max_blob_bytes{2048};
  uint32_t max_allocs{0};
  uint32_t max_steps{1024};
};

class ParserBudget {
 public:
  explicit ParserBudget(const ParserBudgetConfig& cfg) : cfg_(cfg) {}

  bool consume_depth(uint32_t d = 1) {
    if (d > cfg_.max_depth || depth_ > cfg_.max_depth - d) return false;
    depth_ += d;
    return depth_ <= cfg_.max_depth;
  }
  bool consume_field(uint32_t f = 1) {
    if (f > cfg_.max_fields || fields_ > cfg_.max_fields - f) return false;
    fields_ += f;
    return fields_ <= cfg_.max_fields;
  }
  bool consume_varint(uint32_t b = 1) {
    if (b > cfg_.max_varint_bytes || varint_bytes_ > cfg_.max_varint_bytes - b) return false;
    varint_bytes_ += b;
    return varint_bytes_ <= cfg_.max_varint_bytes;
  }
  bool consume_blob(uint32_t b) {
    if (b > cfg_.max_blob_bytes || blob_bytes_ > cfg_.max_blob_bytes - b) return false;
    blob_bytes_ += b;
    return blob_bytes_ <= cfg_.max_blob_bytes;
  }
  bool consume_alloc(uint32_t a = 1) {
    if (a > cfg_.max_allocs || allocs_ > cfg_.max_allocs - a) return false;
    allocs_ += a;
    return allocs_ <= cfg_.max_allocs;
  }
  bool consume_steps(uint32_t s = 1) {
    if (s > cfg_.max_steps || steps_ > cfg_.max_steps - s) return false;
    steps_ += s;
    return steps_ <= cfg_.max_steps;
  }

 private:
  ParserBudgetConfig cfg_{};
  uint32_t depth_{0};
  uint32_t fields_{0};
  uint32_t varint_bytes_{0};
  uint32_t blob_bytes_{0};
  uint32_t allocs_{0};
  uint32_t steps_{0};
};

} // namespace guard
