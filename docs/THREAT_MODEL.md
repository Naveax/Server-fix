# Threat Model

## Primary Threats
1. Volumetric UDP floods that saturate socket buffers, CPU, and worker loops.
2. Malformed datagrams intended to trigger parser or state-machine instability.
3. Fragmentation abuse to increase reassembly pressure and packet ambiguity.
4. Reflection/amplification pressure against operator origin endpoints.
5. Stateful exhaustion via large source fanout (IP/session/bucket growth).
6. Queue pressure causing latency spikes, drops, and control-path starvation.

## Defensive Controls
1. Strict datagram policy:
   - hard max datagram size
   - min datagram size
   - early drop on invalid envelopes
2. Fragment policy:
   - default policy set to drop fragments where reliably observable
   - best-effort limitation documented when UDP API cannot expose fragment metadata
3. Stateless cookie gate (optional):
   - challenge unknown endpoints before forwarding in strict mode
   - compact challenge payloads
   - challenge responses are rate-limited
4. Multi-scope token buckets:
   - global pps/bps
   - per-IP pps/bps
   - optional subnet pps/bps (`/24`, `/64` defaults configurable)
5. Bounded-memory state:
   - fixed-size per-IP and per-subnet bucket stores with eviction
   - max session cap
   - bounded cookie peer tracking
6. Queue hardening:
   - telemetry lane `drop_oldest`
   - critical lane `drop_oldest` (preferred), `drop_newest`, or `block_with_timeout`
   - queue depth visibility in metrics
7. Fast fail behavior:
   - parse/validation failures are dropped immediately
   - no unbounded retries or heap growth per packet

## Residual Limitations
1. Inbound IP fragmentation metadata is not universally exposed by high-level UDP socket APIs.
2. This layer improves operator-owned edge stability but is not a substitute for upstream network
   filtering capacity.
