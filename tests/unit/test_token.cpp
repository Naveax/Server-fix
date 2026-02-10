#include "guard/Token.h"
#include "guard/Util.h"
#include <cassert>

using namespace guard;

void test_token() {
  TokenKey key{};
  key.key_id = 1;
  for (size_t i = 0; i < key.secret.size(); ++i) key.secret[i] = static_cast<uint8_t>(i);
  TokenKeyring kr{};
  kr.current = key;
  kr.previous = key;
  kr.bucket_ms = 1000;
  kr.max_skew_buckets = 1;

  TokenFields f{};
  f.pop_id = 10;
  f.server_id = 20;
  f.proto_ver = 1;
  f.time_bucket = 100;
  f.ip_prefix_hash = {1,2,3,4,5,6,7,8};

  auto tok = token_mint(f, key);
  auto res = token_verify(tok, kr, 100);
  assert(res.ok);
  assert(res.fields.pop_id == 10);

  auto res2 = token_verify(tok, kr, 200);
  assert(!res2.ok);
}
