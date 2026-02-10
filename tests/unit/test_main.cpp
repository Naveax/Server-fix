#include <iostream>

void test_token();
void test_amplification();
void test_rate_limiter();
void test_parser_budget();
void test_queue_guard();
void test_risk();

int main() {
  test_token();
  test_amplification();
  test_rate_limiter();
  test_parser_budget();
  test_queue_guard();
  test_risk();
  std::cout << "guard_tests ok\n";
  return 0;
}
