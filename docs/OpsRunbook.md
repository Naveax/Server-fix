# Ops Runbook

## SLOs
- Tick time p99 <= 50ms.
- Queue depth stays below safe-mode thresholds 99.9% of time.
- Inbound drop ratio <= 2% under normal load.
- False-positive enforcement < 0.1% of valid sessions.
- Match survival under overload without restart or crash.

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
