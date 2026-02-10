#include "guard/Token.h"
#include <cstddef>
#include <cstdint>
#include <vector>

using namespace guard;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  TokenKey key{};
  key.key_id = 1;
  TokenKeyring kr{};
  kr.current = key;
  kr.previous = key;
  kr.bucket_ms = 1000;
  kr.max_skew_buckets = 1;

  std::vector<uint8_t> tok(data, data + size);
  (void)token_verify(tok, kr, 0);
  return 0;
}
