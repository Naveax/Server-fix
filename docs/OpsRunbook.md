# Ops Runbook

## SLO Targets
- Proxy overhead: p50 <= 1ms, p99 <= 5ms.
- Tick stability: tick p99 <= 50ms.
- Queue health: queue depth remains below safe-mode thresholds 99.9% of time.
- Drop quality: inbound drop ratio <= 2% under normal load.
- Enforcement quality: false positives < 0.1% of valid sessions.

## Drop Policy
- Drop invalid datagrams, failed challenge/cookie packets (strict mode), rate-limited packets, and queue-overflow packets.
- Telemetry drops under overload are expected; critical-lane drops are incident-level.

## Queue Limit Semantics
- `telemetry` lane: drop-oldest under pressure.
- `critical` lane: drop-newest or bounded block-with-timeout (never unbounded blocking).
- In worker-sharded deployments, queue and session limits are enforced per worker unless explicitly normalized.

## Fail-Open vs Fail-Closed
- `fail-closed`: deny unknown/invalid clients until validation succeeds; use for high-risk deployments.
- `fail-open` (compatibility mode): allow unknown clients while collecting validation telemetry; use during rollout/migration.
- Rollout guidance: start fail-open, verify metrics, then move to fail-closed.

## Operator Tuning Notes
- Size UDP socket receive/send buffers for expected PPS/BPS and monitor kernel-level drops.
- Align worker count, NIC RSS queues, and IRQ affinity with CPU topology.
- Watch per-core saturation, softirq backlog, queue depth, and drop reasons as first-line capacity signals.
- Tune conservatively and validate with staging load before production changes.

## Out Of Scope
- This runbook is for operator-owned and explicitly authorized infrastructure only.
- It does not cover patching or controlling third-party ranked/matchmaking backends.

## Safe Mode
- Trigger when tick p99 or queue depth exceeds threshold.
- Reduce noncritical replication and telemetry.
- Preserve core gameplay updates and input handling.

## Incident Response
1. Confirm whether safe mode is active.
2. Inspect inbound drop reasons and amplification events.
3. Increase sampling rate for a short window.
4. Apply or tighten rate limits and greylist thresholds.
5. Validate recovery and roll back temporary limits.

## Autonomous Mitigation
- Local nodes can apply immediate policy updates.
- Control plane distributes block/grey list and thresholds.
- Avoid centralized bottlenecks; prefer eventual consistency.

## References
- Cloudflare L4Drop: https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/
- Cloudflare autonomous edge DDoS: https://blog.cloudflare.com/deep-dive-cloudflare-autonomous-edge-ddos-protection/
- RFC 9000: https://datatracker.ietf.org/doc/html/rfc9000
- RFC 8085: https://datatracker.ietf.org/doc/html/rfc8085
- OSS-Fuzz: https://google.github.io/oss-fuzz/
- libFuzzer: https://llvm.org/docs/LibFuzzer.html
