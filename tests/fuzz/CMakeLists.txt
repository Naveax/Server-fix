# libFuzzer targets for NX

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "Fuzzers require Clang. Re-configure with -DCMAKE_CXX_COMPILER=clang++")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(nx_fuzz_config INTERFACE)
target_compile_options(nx_fuzz_config INTERFACE
  -O1 -g -fno-omit-frame-pointer
  -fsanitize=fuzzer,address,undefined
  -fno-sanitize-recover=all
  -gdwarf-4
)
target_link_options(nx_fuzz_config INTERFACE
  -fsanitize=fuzzer,address,undefined
  -fuse-ld=lld
)

function(nx_add_fuzzer name src)
  add_executable(${name} ${src})
  # Guard.cpp -> SandboxClient sembolleri guard_sandbox'ta: static link order önemli
  target_link_libraries(${name} PRIVATE guard guard_sandbox nx_fuzz_config)
endfunction()

nx_add_fuzzer(fuzz_packet_end2end ${CMAKE_CURRENT_LIST_DIR}/fuzz_packet_end2end.cpp)
nx_add_fuzzer(fuzz_parser        ${CMAKE_CURRENT_LIST_DIR}/fuzz_parser.cpp)
nx_add_fuzzer(fuzz_token         ${CMAKE_CURRENT_LIST_DIR}/fuzz_token.cpp)
