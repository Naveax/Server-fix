# UDP Game Server Resilience Guard -- Context

## Goals
- Provide a defensive-only, generic reference package for UDP game servers that prevents crashes, tick stalls, and cascading failures.
- Offer a C++17/20 library with bounded-work parsing, admission control, anti-amplification enforcement, multi-dimensional rate limits, queue backpressure, and deterministic risk scoring.
- Enable deployment flexibility with optional kernel (XDP/eBPF) and proxy layers, plus a parser sandbox for crash containment.
- Emphasize performance (O(1) hot path), observability, and safe failure modes.
- Make integration straightforward for engine teams via clear interfaces and docs.

## Non-goals
- No offensive guidance, exploit steps, or bypass instructions.
- No game- or studio-specific protocol assumptions.
- No claim of "perfect protection." The system must be measurable, testable, and fail-soft.

## Threat Taxonomy (Defensive Framing)
- Volumetric L3/L4 floods: mitigate at edge/relay, kernel/XDP, and proxy.
- Spoofed-source reflection/amplification risks: address validation, anti-amplification, ingress filtering notes.
- State-exhaustion / handshake abuse: stateless tokens, DTLS-cookie precedent, admission control.
- CPU/parse pressure, queue pressure, tick budget overruns: bounded-work parser, CPU budget firewall, queue guardrails, safe mode.
- Reconnect churn / session thrash: churn tracking and rate controls.
- "Match disruptor" behavior (generic): risk scoring and enforcement hooks.
- Internal failures: noisy neighbor, lock contention, kernel drops, NIC overruns: isolation guidance and circuit breakers.

## Architecture Layers
- Edge/Relay: hide origin IPs, authenticate/encrypt, coarse rate limits; reduces attack surface but does not replace in-server guards.
- Kernel/XDP: early drop for high PPS and obvious invalid traffic; minimal work per packet.
- Proxy (UDP): centralized admission, rate limits, metrics without changing game binaries.
- App/Server Guard: authoritative validation, anti-amplification, parsing, rate limiting, queue/backpressure, risk scoring.
- Sandbox Parser: crash containment and timeouts for untrusted decode.
- Control Plane: distributes policies and thresholds; supports autonomous local mitigation.

## Acceptance Criteria
- Hot path O(1) per packet with bounded memory growth and minimal locks.
- Pre-validation egress capped to <= 3x ingress bytes per flow/prefix.
- Stateless address validation with short TTL Retry-like tokens and DTLS-cookie fallback precedent.
- Bounded-work parsing with explicit budgets and overflow-safe counters; no packet-driven asserts/restarts.
- Queue/backpressure guardrails and safe mode prevent tick stalls.
- Deterministic risk scorer with explainable reason codes and conservative thresholds.
- Observability: Prometheus-style metrics and SLOs with low overhead sampling.
- Tests: unit, property, and fuzz targets for tokens, limits, counters, and parsing.
