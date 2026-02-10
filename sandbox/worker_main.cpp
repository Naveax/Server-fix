#include "guard/Parser.h"
#include <cstdint>
#include <iostream>
#include <vector>

using namespace guard;

int main() {
  ParserBudgetConfig cfg{};
  while (true) {
    uint8_t hdr[2];
    if (!std::cin.read(reinterpret_cast<char*>(hdr), 2)) break;
    uint16_t len = (static_cast<uint16_t>(hdr[0]) << 8) | hdr[1];
    std::vector<uint8_t> buf(len);
    if (!std::cin.read(reinterpret_cast<char*>(buf.data()), len)) break;
    PacketView pkt{buf.data(), buf.size()};
    auto res = parse_example_frame(pkt, cfg);
    uint8_t out = res.ok ? 0 : 1;
    std::cout.write(reinterpret_cast<const char*>(&out), 1);
    std::cout.flush();
  }
  return 0;
}
