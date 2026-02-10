# Tasks

1. Objective: Create base repo layout and CMake skeleton.
Files: CMakeLists.txt, build/ (presets), docs/ (placeholders).
Validation: `cmake -S . -B build && cmake --build build`.

2. Objective: Implement core guard interfaces and adapters (on_recv/on_send/on_tick).
Files: guard/include/Guard.h, guard/src/Guard.cpp.
Validation: `cmake --build build`.

3. Objective: Implement address validation tokens (mint/verify) and anti-amplification accounting.
Files: guard/include/Token.h, guard/src/Token.cpp, guard/include/Amplification.h, guard/src/Amplification.cpp.
Validation: unit tests `ctest -R token|amplification`.

4. Objective: Implement bounded-work parser framework and precheck utilities.
Files: guard/include/ParserBudget.h, guard/src/ParserBudget.cpp, guard/include/Precheck.h.
Validation: unit tests `ctest -R parser_budget`.

5. Objective: Implement multi-dimensional rate limiter (pre/post auth) with cost weights.
Files: guard/include/RateLimiter.h, guard/src/RateLimiter.cpp.
Validation: unit + property tests `ctest -R rate_limiter`.

6. Objective: Implement queue/backpressure guards and tick budget controls.
Files: guard/include/QueueGuard.h, guard/src/QueueGuard.cpp.
Validation: unit tests `ctest -R queue_guard`.

7. Objective: Implement deterministic risk scorer and enforcement hooks.
Files: guard/include/RiskScorer.h, guard/src/RiskScorer.cpp.
Validation: unit tests `ctest -R risk`.

8. Objective: Implement parse sandbox worker and IPC with timeouts/backpressure.
Files: sandbox/ (worker + IPC), guard/include/SandboxClient.h, guard/src/SandboxClient.cpp.
Validation: integration test `ctest -R sandbox`.

9. Objective: Add tests (unit, property, fuzz targets) and sanitizer builds.
Files: tests/unit/*, tests/property/*, tests/fuzz/*.
Validation: `ctest` and fuzz build `cmake -S . -B build-fuzz -DGUARD_FUZZ=ON`.

10. Objective: Write docs (ThreatModel, Architecture, IntegrationGuide, OpsRunbook, Metrics).
Files: docs/ThreatModel.md, docs/Architecture.md, docs/IntegrationGuide.md, docs/OpsRunbook.md, docs/Metrics.md.
Validation: manual review for completeness.

11. Objective: Add optional XDP policy skeleton and proxy config examples.
Files: xdp/, proxy/.
Validation: `cmake --build build` (docs-only).

12. Objective: Add disclosure report template and finalize acceptance criteria.
Files: report/DisclosureTemplate.md, docs/CONTEXT.md updates.
Validation: manual review.
