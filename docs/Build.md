# Build Notes

## Standard Build
- Configure: `cmake --preset default`
- Build: `cmake --build build -j`
- Test: `ctest --test-dir build`

## Fuzz Build (libFuzzer)
- Requires Clang/LLVM. GCC does not support `-fsanitize=fuzzer`.
- Configure: `cmake --preset fuzz` (or set `CC=clang CXX=clang++`).
- Build: `cmake --build build-fuzz -j`
- Run:
  - `./build-fuzz/fuzz_token corpus/token -max_total_time=120`
  - `./build-fuzz/fuzz_parser -max_total_time=120`
  - `./build-fuzz/fuzz_packet_end2end corpus/packet -dict=corpus/packet/dict.txt -max_total_time=120`

## WSL Notes
- For best performance and correct timestamps, build within the WSL Linux filesystem (e.g. `~/project`) instead of `/mnt/c` or `/mnt/d`.

## Windows + WSL Build Directories
- Do not reuse the same CMake build directory between WSL and Windows. CMake caches absolute paths and will error if the source/build paths change (e.g. `/mnt/d/...` vs `D:\\...`).
- Use separate build dirs:
  - WSL: `cmake -S . -B build-wsl && cmake --build build-wsl -j && ctest --test-dir build-wsl --output-on-failure`
  - PowerShell: `cmake -S . -B build-win; cmake --build build-win --parallel; ctest --test-dir build-win --output-on-failure`
- If you already have a mismatched cache, delete the build dir and re-configure in the same environment.
