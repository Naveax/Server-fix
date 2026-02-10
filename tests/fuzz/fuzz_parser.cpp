#include "guard/Parser.h"
#include <cstddef>
#include <cstdint>

using namespace guard;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  PacketView pkt{data, size};
  ParserBudgetConfig cfg{};
  (void)parse_example_frame(pkt, cfg);
  return 0;
}
