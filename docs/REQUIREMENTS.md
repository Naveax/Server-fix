# Requirements

## MUST
1. Provide a C++17/20 guard library with public headers and source implementation.
2. Enforce QUIC-style anti-amplification: before address validation, cap egress to <= 3x ingress bytes per flow/prefix (RFC 9000).
3. Implement stateless address validation via Retry-like token bound to pop_id, server_id, proto_ver, time-bucket, and IP-prefix hash; short TTL; rotation; replay resistance.
4. Provide DTLS-cookie-style fallback as a precedent for stateless validation during handshake (RFC 9147).
5. Implement bounded-work parsing with explicit per-packet budgets: max depth, fields, varint length, blob sizes, allocations, and step counters. Fail-fast drop with reason codes.
6. Ensure no packet-driven code path can trigger restart/exit/assert; network-facing errors return fail-soft.
7. Enforce multi-dimensional rate limiting with separate pre-auth and post-auth limiters.
8. Rate limiting keys must include: src_ip, /24 prefix, ASN bucket (abstract input), account_id, session_id, pop_id.
9. Rate limiting dimensions must include: pps, bytes/s, msg-type budgets, invalid_ratio, token_fail_rate, reconnect_churn, parse_cost_budget, queue_pressure_contribution.
10. Implement queue/backpressure guards: bounded queues, deterministic shedding, per-client budgets, safe mode, and circuit breakers based on tick p99 and queue depth.
11. Implement a deterministic risk scorer (OK/SUSPECT/BLOCK) using cheap features with decay and recovery; provide explainable reason codes.
12. Provide a parser sandbox process with timeouts, backpressure, and crash containment; restart on failure.
13. Provide Prometheus-style metrics, SLO targets, and an ops runbook.
14. Provide unit tests, property tests, and fuzz targets (libFuzzer style) for tokens, limits, counters, parsers, and IPC.
15. Include references to RFC 9000, RFC 9147, RFC 8085, RFC 2827, XDP/eBPF L4Drop, autonomous edge mitigation, SDR, Quilkin, OSS-Fuzz, and libFuzzer in docs/comments as rationale.

## SHOULD
1. Provide optional XDP/eBPF policy skeleton and policy spec for early drop and sampling.
2. Provide optional UDP proxy config examples with filters: admission, rate_limit, metrics, routing.
3. Provide an optional sandbox IPC implementation for both Windows (named pipe) and POSIX (UDS/pipe).
4. Provide build presets and sanitizer options (ASan/UBSan) for fuzzing.
5. Provide guidance for isolation and blast-radius containment (per-match process/container/VM).
