#pragma once
#include <cstddef>
#include <cstdint>
#include "Common.h"
#include "ParserBudget.h"

namespace guard {

enum class ParseError : uint8_t {
  None = 0,
  Truncated,
  BudgetExceeded,
  InvalidVarint,
};

struct ParseResult {
  bool ok{false};
  ParseError error{ParseError::None};
  uint32_t steps{0};
};

class BoundedReader {
 public:
  BoundedReader(const PacketView& pkt, const ParserBudgetConfig& cfg);

  bool read_u8(uint8_t& out);
  bool read_u16(uint16_t& out);
  bool read_bytes(size_t len, PacketView& out);
  bool read_varint(uint64_t& out);
  bool skip(size_t len);
  ParseError error() const { return error_; }
  uint32_t steps() const { return steps_; }

 private:
  bool consume_step(uint32_t s = 1);

  const uint8_t* data_{nullptr};
  size_t len_{0};
  size_t pos_{0};
  ParserBudget budget_;
  ParseError error_{ParseError::None};
  uint32_t steps_{0};
};

// Example bounded parse of a generic frame: [type:1][len:2][payload:len]
ParseResult parse_example_frame(const PacketView& pkt, const ParserBudgetConfig& cfg);

} // namespace guard
