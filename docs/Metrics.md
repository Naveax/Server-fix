# Metrics

## Prometheus-Style Names
- `guard_inbound_drop_total{reason}`
- `guard_outbound_drop_total{reason}`
- `guard_greylist_total`
- `guard_token_fail_total`
- `guard_invalid_parse_total`
- `guard_amplification_budget_exceeded_total`
- `guard_queue_in_depth`
- `guard_queue_out_depth`
- `guard_safe_mode_active`
- `guard_risk_score_histogram`
- `guard_sandbox_timeout_total`
- `guard_sandbox_crash_total`
- `guard_tick_time_ms{p50,p95,p99}`

## Sampling Strategy
- Default head-based sampling at low rate.
- Incident mode: increase sampling for short intervals.
- Tail-based sampling for rare error reason codes.

## Dashboards Outline
- Tick latency and safe mode status.
- Inbound/outbound drops by reason.
- Amplification budget usage.
- Rate limit and greylist events.
- Sandbox timeouts/crashes.
