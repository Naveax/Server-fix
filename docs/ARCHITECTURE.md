# Architecture

## Scope
RocketLeagueServerFix provides a generic, vendor-agnostic UDP edge mitigation and relay layer for
game-server operators. The system is intended to sit in front of an operator-owned origin and
reduce instability from malformed traffic, abusive packet rates, and queue pressure while
preserving low-latency forwarding for valid traffic.

This repository does not patch or control third-party ranked infrastructure. Operators must deploy
this layer on infrastructure they own or manage.

## Design Goals
1. Security hardening at the UDP edge:
   - strict packet size validation
   - bounded memory/state budgets
   - multi-scope rate limiting (global/IP/subnet)
   - optional stateless cookie gate for first-seen peers
2. Low-latency forwarding path:
   - lock-minimized worker sharding with `SO_REUSEPORT`
   - optional Linux batched I/O (`recvmmsg`/`sendmmsg`) via `nx_netio`
   - bounded queue policies to preserve critical traffic under pressure
3. Deployability:
   - config-driven operation
   - Prometheus metrics export
   - systemd and container packaging examples

## High-Level Data Path
1. Ingress UDP datagram arrives on worker socket.
2. Datagram is validated against strict policy (size, framing checks, optional fragment policy).
3. Optional cookie gate decides `forward | challenge | drop`.
4. Multi-scope token buckets apply admission control.
5. Packet is classified into lane (`critical` or `telemetry`) and queued with bounded policy.
6. Session worker forwards to upstream origin.
7. Response path applies lane scheduling and bounded egress queueing back to client.
8. Metrics are emitted for packets, drops, rate limits, queue depth, and net I/O syscall behavior.

## Components
- `crates/nx_proxy`: main edge proxy/mitigation runtime.
- `crates/nx_netio`: hot-path UDP I/O abstraction with Linux `mmsg` support and portable fallback.
- `crates/nx_metrics`: metrics counters/gauges for observability.
- `crates/nx_fuzz`: fuzz targets for validator/decoder hardening.
- `crates/nx_bench`: local benchmark harness for throughput/latency regression tracking.

## Runtime Semantics
1. Worker sharding:
   - `SO_REUSEPORT` workers keep per-worker state to avoid cross-worker locks.
   - `rate_limit.global_*` and `proxy.max_sessions` are currently enforced per worker, not
     process-global. Effective aggregate capacity scales with `worker_count`.
2. Cookie gate:
   - `strict` mode requires a valid cookie response for first-seen peers.
   - after verification, raw packets from that peer are accepted until TTL expiry.
3. Fragment policy:
   - `drop_udp_fragments` is best-effort with standard UDP socket APIs.
   - when fragment metadata is unavailable from the OS/socket interface, exact fragment rejection
     cannot be guaranteed.
4. Address family handling:
   - IPv4 and IPv6 are supported.
   - on IPv6 listeners, operators should explicitly choose dual-stack or v6-only behavior per
     deployment policy.

## Optional Integrations
RLBot-specific artifacts are intentionally isolated under `docs/optional/rlbot/` and are not part
of the default product scope.
