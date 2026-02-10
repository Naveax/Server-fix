#include "guard/Parser.h"

namespace guard {

BoundedReader::BoundedReader(const PacketView& pkt, const ParserBudgetConfig& cfg)
    : data_(pkt.data), len_(pkt.len), budget_(cfg) {}

bool BoundedReader::consume_step(uint32_t s) {
  steps_ += s;
  if (!budget_.consume_steps(s)) {
    error_ = ParseError::BudgetExceeded;
    return false;
  }
  return true;
}

bool BoundedReader::read_u8(uint8_t& out) {
  if (!consume_step()) return false;
  if (pos_ + 1 > len_) { error_ = ParseError::Truncated; return false; }
  out = data_[pos_++];
  budget_.consume_field();
  return true;
}

bool BoundedReader::read_u16(uint16_t& out) {
  if (!consume_step()) return false;
  if (pos_ + 2 > len_) { error_ = ParseError::Truncated; return false; }
  out = static_cast<uint16_t>((data_[pos_] << 8) | data_[pos_ + 1]);
  pos_ += 2;
  budget_.consume_field();
  return true;
}

bool BoundedReader::read_bytes(size_t len, PacketView& out) {
  if (!consume_step()) return false;
  if (!budget_.consume_blob(static_cast<uint32_t>(len))) {
    error_ = ParseError::BudgetExceeded;
    return false;
  }
  if (pos_ + len > len_) { error_ = ParseError::Truncated; return false; }
  out.data = data_ + pos_;
  out.len = len;
  pos_ += len;
  return true;
}

bool BoundedReader::read_varint(uint64_t& out) {
  out = 0;
  uint32_t shift = 0;
  for (uint32_t i = 0; i < 10; ++i) {
    if (!consume_step()) return false;
    if (!budget_.consume_varint(1)) { error_ = ParseError::BudgetExceeded; return false; }
    if (pos_ + 1 > len_) { error_ = ParseError::Truncated; return false; }
    uint8_t b = data_[pos_++];
    out |= static_cast<uint64_t>(b & 0x7F) << shift;
    if ((b & 0x80) == 0) return true;
    shift += 7;
  }
  error_ = ParseError::InvalidVarint;
  return false;
}

bool BoundedReader::skip(size_t len) {
  if (!consume_step()) return false;
  if (!budget_.consume_blob(static_cast<uint32_t>(len))) {
    error_ = ParseError::BudgetExceeded;
    return false;
  }
  if (pos_ + len > len_) { error_ = ParseError::Truncated; return false; }
  pos_ += len;
  return true;
}

ParseResult parse_example_frame(const PacketView& pkt, const ParserBudgetConfig& cfg) {
  ParseResult res{};
  BoundedReader br(pkt, cfg);
  uint8_t type = 0;
  uint16_t len = 0;
  if (!br.read_u8(type)) { res.error = br.error(); return res; }
  if (!br.read_u16(len)) { res.error = br.error(); return res; }
  PacketView payload{};
  if (!br.read_bytes(len, payload)) { res.error = br.error(); return res; }
  (void)type;
  res.ok = true;
  res.error = ParseError::None;
  res.steps = br.steps();
  return res;
}

} // namespace guard
