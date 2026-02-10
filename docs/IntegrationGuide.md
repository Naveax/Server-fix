# Integration Guide

## Hook Points
- Ingress: call `Guard::on_packet_receive()` for each UDP packet.
- Egress: call `Guard::on_packet_send()` for each response packet.
- Tick: call `Guard::on_tick_end()` with tick duration and queue depths.
- Sandbox: route untrusted decode to the sandbox worker (or in-process fallback).

## Suggested Flow
1. Precheck length and protocol version.
2. Apply address validation with Retry-like tokens.
3. Enforce anti-amplification before validation (egress <= 3x ingress) for all responses.
4. Run bounded parsing with strict budgets.
5. Apply multi-dimensional rate limits.
6. Apply queue and tick budget guards.
7. Emit metrics and reason codes.
8. Invoke enforcement hooks (greylist/kick) via `IEnforcementHook`.

## Example Adapter Interface
- `on_packet_receive(PacketView, IngressContext)`
- `on_packet_send(ByteCount, EgressContext)`
- `on_tick_end(tick_ms, in_depth, out_depth)`

## Integration Notes
- Provide `pop_id`, `server_id`, and `proto_ver` at minimum.
- If available, supply `account_id`, `session_id`, and ASN bucket for stronger limits.
- Set `IngressContext::priority` and `EgressContext::priority` for drop/degrade policies.
- Populate `IngressContext::inbound_depth` and `EgressContext::outbound_depth` if available.
- Provide `IngressContext::token` for stateless validation.
- When token validation succeeds, mark the connection/flow as validated for future calls.
- Provide `IngressContext::msg_type` and `msg_cost` for cost-weighted budgets.
- Use `ParserBudget` and `BoundedReader` utilities for safe parsing.
- Ensure network-facing code paths never call restart/exit/assert based on packet contents.
- Metrics integration is via `IMetricSink` (Prometheus exporter can be attached externally).

## Sandbox Integration
- Preferred: separate worker process with timeouts and backpressure.
- Fallback: in-process bounded parser if sandbox is disabled.
- Configure `SandboxConfig::worker_path` to the `sandbox_worker` executable.
- Use `SandboxConfig::inprocess_fallback` for environments where a worker process is not allowed.
- `GuardConfig::sandbox` allows per-deployment overrides (timeouts, in-process fallback).

## References (Rationale)
- RFC 9000: https://datatracker.ietf.org/doc/html/rfc9000
- RFC 9147: https://www.rfc-editor.org/rfc/rfc9147.html
- RFC 8085: https://datatracker.ietf.org/doc/html/rfc8085
