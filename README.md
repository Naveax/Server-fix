# RocketLeagueServerFix

Defensive UDP edge mitigation layer and guard components for operator-owned game server deployments.

## Scope
- Provides a vendor-agnostic UDP mitigation/proxy path (`nx_proxy`) with rate limiting, queue backpressure, packet validation, and optional challenge/cookie gating.
- Includes optional anomaly/smurf model hooks (heuristic or TorchScript).
- Intended for deployment by server operators on infrastructure they control.

## Threat Model
- Volumetric UDP floods, malformed datagrams, queue pressure, and state exhaustion.
- Packet manipulation attempts using invalid length/checksum envelopes.
- Client sync drift spikes and suspicious MMR swings that correlate with unstable sessions.

## Out Of Scope
- Patching or controlling third-party ranked/matchmaking infrastructure.
- Offensive tooling, exploit development, or testing against infrastructure you do not own.

## Quick Start

### Rust Workspace
```bash
cargo build --workspace
cargo test --all
```

Run the UDP proxy:
```bash
cargo run -p nx_proxy -- --config config/dev.toml
```

### CMake Guard Build
```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## Configuration
- `config/example.toml`: production-oriented template.
- `config/dev.toml`: local development defaults.
- Per-IP token bucket shortcut: `[rate_limit].ddos_limit = 500.0`.
- Queue/backpressure defaults in the templates are tuned for freshness under overload:
  - `[proxy].critical_overflow_policy = "drop_oldest"` (prefer newest control/state; avoid stale backlog).
  - Keep `[proxy].telemetry_queue_capacity` smaller than `[proxy].critical_queue_capacity` to prevent telemetry from consuming queue budget.
  - Optional: downstream stale-drop TTLs (`[proxy].downstream_*_ttl_millis`) can prevent delivering very late packets during overload.
- Optional socket buffer tuning:
  - `[proxy].socket_recv_buffer_bytes` and `[proxy].socket_send_buffer_bytes` tune `SO_RCVBUF` / `SO_SNDBUF` for worker and per-session upstream sockets.
  - Use powers-of-two sized values (for example `2097152` or `4194304`) and verify effective values at OS level, since kernels can clamp.
- Anomaly controls: `[anomaly]` with `anomaly_threshold`, `client_sync_check`, and `model`.
- Packet integrity controls: `[packet_validation]` with `strict_mode` and `require_checksum`.
- MMR/smurf controls: `[mmr]` with `mmr_threshold = 0.8` and optional Torch model path.

## Other Bugs Mitigation
- **Packet Manipulation**: strict packet validation enforces size limits plus optional checksum/length envelope verification.
- **Client Predictive Lag**: anomaly score now includes optional client sync drift parsing (`SYNC:<ms>`), combined with traffic-rate features.
- **MMR Smurf Signals**: optional detector parses `MMR:<value>` updates and flags extreme short-window swings.

Loopback-only manipulation PoC:
```bash
cargo run -p nx_proxy --bin nx_packet_manip_sim -- --target 127.0.0.1:7000 --pps 2000 --invalid-ratio 0.5
```

Flood PoC (authorized local testing only):
```bash
cargo run -p nx_proxy --bin nx_flood_sim -- --target 127.0.0.1:7000 --pps 10000 --duration-secs 5
```

Train/export TorchScript LSTM anomaly model (`[1,10,3] -> hidden 64 -> sigmoid`):
```bash
cargo run -p nx_proxy --release --features torch_train --bin train -- --samples 1000 --anomaly-ratio 0.5 --output anomaly_model.pt --roc-plot-output roc_curve.svg
```

Native libtorch mode (opt-in):
```bash
export LIBTORCH=/path/to/libtorch
export LIBTORCH_USE_PYTORCH=1
cargo run -p nx_proxy --release --features torch_train_full,cuda_anomaly --bin train -- --samples 1000 --output anomaly_model.pt --roc-plot-output roc_curve.svg
```

## Benchmark Notes
`cargo bench -p nx_bench --features cuda_anomaly --bench udp_fast_path` now reports:
- anomaly latency/drop metrics
- packet validation latency/drop ratio
- MMR detector latency/drop ratio

## Metrics Dashboard Quick Start
Enable metrics in config and scrape `GET /metrics` from `[metrics].listen_addr`.

Useful PromQL starters:
- UDP packet drop ratio:
  - `sum(rate(nx_proxy_udp_dropped_total[1m])) / clamp_min(sum(rate(nx_proxy_udp_pkts_in_total[1m])), 1)`
- Queue pressure by lane:
  - `max(nx_proxy_udp_queue_depth{direction="upstream_to_client"}) by (lane)`
- Rate-limit pressure:
  - `sum(rate(nx_proxy_udp_rate_limited_total[1m])) by (scope)`
- Top drop reasons:
  - `topk(8, sum(rate(nx_proxy_udp_dropped_total[5m])) by (reason))`

## Security Note
Use this project only on systems and networks you own or are explicitly authorized to operate.

## Documentation
- Build notes: `docs/Build.md`
- Architecture: `docs/ARCHITECTURE.md`
- Deployment: `docs/DEPLOYMENT.md`
