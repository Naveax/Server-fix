cmake_minimum_required(VERSION 3.16)
project(udp_guard LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(GUARD_BUILD_TESTS "Build tests" ON)
option(GUARD_FUZZ "Build fuzz targets" OFF)
option(GUARD_ENABLE_SANDBOX "Enable sandbox worker" ON)

add_library(guard
    guard/src/Guard.cpp
    guard/src/Token.cpp
    guard/src/Amplification.cpp
    guard/src/RateLimiter.cpp
    guard/src/ParserBudget.cpp
    guard/src/Parser.cpp
    guard/src/Precheck.cpp
    guard/src/QueueGuard.cpp
    guard/src/RiskScorer.cpp
    guard/src/crypto/sha256.cpp
    guard/src/Metrics.cpp
    guard/src/Util.cpp
)

target_include_directories(guard PUBLIC guard/include)

target_compile_definitions(guard PUBLIC $<$<BOOL:${GUARD_ENABLE_SANDBOX}>:GUARD_ENABLE_SANDBOX>)

if(GUARD_ENABLE_SANDBOX)
  add_library(guard_sandbox
      guard/src/SandboxClient.cpp
  )
  target_link_libraries(guard_sandbox PRIVATE guard)
  target_include_directories(guard_sandbox PUBLIC guard/include)

  add_executable(sandbox_worker sandbox/worker_main.cpp)
  target_link_libraries(sandbox_worker PRIVATE guard)
endif()

if(GUARD_BUILD_TESTS)
  enable_testing()
  add_executable(guard_tests
      tests/unit/test_main.cpp
      tests/unit/test_token.cpp
      tests/unit/test_amplification.cpp
      tests/unit/test_rate_limiter.cpp
      tests/unit/test_parser_budget.cpp
      tests/unit/test_queue_guard.cpp
      tests/unit/test_risk.cpp
  )
  target_link_libraries(guard_tests PRIVATE guard)
  add_test(NAME guard_tests COMMAND guard_tests)

  add_executable(guard_property_tests
      tests/property/test_properties.cpp
  )
  target_link_libraries(guard_property_tests PRIVATE guard)
  add_test(NAME guard_property_tests COMMAND guard_property_tests)
endif()

if(GUARD_FUZZ)
  add_subdirectory(tests/fuzz)
endif()
