#include "guard/Parser.h"
#include <cassert>
#include <vector>

using namespace guard;

void test_parser_budget() {
  std::vector<uint8_t> pkt = {0x01, 0x00, 0x03, 0xAA, 0xBB, 0xCC};
  PacketView view{pkt.data(), pkt.size()};
  ParserBudgetConfig cfg{};
  cfg.max_blob_bytes = 2;
  auto res = parse_example_frame(view, cfg);
  assert(!res.ok);

  cfg.max_blob_bytes = 4;
  auto res2 = parse_example_frame(view, cfg);
  assert(res2.ok);
}
