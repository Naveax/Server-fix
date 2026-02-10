# Deployment Guide

## systemd Unit Example
Create `config/systemd/nx_proxy.service` and adapt paths as needed:

```ini
[Unit]
Description=nx_proxy UDP edge mitigation service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nxproxy
Group=nxproxy
WorkingDirectory=/opt/rocketleagueserverfix
ExecStart=/opt/rocketleagueserverfix/nx_proxy --config /etc/nx_proxy/example.toml
Restart=always
RestartSec=1
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

## Docker Usage
Build runtime image:

```bash
docker build -t nx-proxy:latest .
```

Run with host networking (recommended for UDP latency and port handling):

```bash
docker run --rm \
  --network host \
  -v /etc/nx_proxy:/etc/nx_proxy:ro \
  nx-proxy:latest \
  --config /etc/nx_proxy/example.toml
```

## Recommended Linux Tuning (Documentation Only)
Adjust according to host capacity and workload profile:

```bash
sysctl -w net.core.rmem_max=268435456
sysctl -w net.core.wmem_max=268435456
sysctl -w net.core.netdev_max_backlog=250000
sysctl -w net.ipv4.udp_mem="262144 524288 1048576"
sysctl -w net.ipv4.udp_rmem_min=16384
sysctl -w net.ipv4.udp_wmem_min=16384
```

NIC/queue considerations:
1. Size RX/TX ring buffers appropriately (`ethtool -G`).
2. Align RSS/RPS queue count with worker count and physical cores.
3. Prefer IRQ affinity planning for stable CPU cache locality.
4. Monitor drops at NIC and socket layers (`ethtool -S`, `/proc/net/softnet_stat`).

## Operational Notes
1. Start with conservative cookie-gate and rate-limit settings in compatibility mode.
2. Observe `udp_dropped_total{reason=...}` and `udp_rate_limited_total{scope=...}` before tightening.
3. Keep queue capacities bounded; increase only with matching CPU/network headroom.
4. If you need process-wide effective limits, pre-divide `rate_limit.global_*` and `proxy.max_sessions`
   by `proxy.worker_count` (these are enforced per worker by design).
