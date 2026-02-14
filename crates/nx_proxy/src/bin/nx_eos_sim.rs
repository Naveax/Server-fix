use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nx_proxy::config::{
    AnomalySection, CookieMode, CookieSection, CriticalOverflowPolicy, FloodSimSection,
    MetricsSection, MmrSection, PacketValidationSection, ProxyConfig, ProxySection,
    RateLimitSection,
};
use nx_proxy::run_proxy;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

const DEFAULT_CLIENTS: usize = 8;
const DEFAULT_TICK_HZ: u64 = 60;
const DEFAULT_DURATION_SECS: u64 = 10;
const DEFAULT_TELEMETRY_PER_TICK: usize = 40;
const DEFAULT_MAX_PACKETS_PER_TICK: usize = 80;
const DEFAULT_JITTER_MS: u64 = 30;
const DEFAULT_DROP_RATE: f64 = 0.03;
const DEFAULT_PROXY_QUEUE_CAPACITY: usize = 96;
const DEFAULT_PROXY_TELEMETRY_QUEUE_CAPACITY: usize = 48;
const DEFAULT_PROXY_CRITICAL_QUEUE_CAPACITY: usize = 64;
const DEFAULT_PROXY_WORKERS: usize = 1;
const DEFAULT_PROXY_BATCH_SIZE: usize = 32;
const DEFAULT_PROXY_CRITICAL_BLOCK_TIMEOUT_MILLIS: u64 = 5;
const DEFAULT_PROXY_DOWNSTREAM_TELEMETRY_TTL_MILLIS: u64 = 0;
const DEFAULT_PROXY_DOWNSTREAM_CRITICAL_TTL_MILLIS: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Direct,
    Proxied,
    Compare,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompareOrder {
    DirectFirst,
    ProxiedFirst,
    Alternate,
}

#[derive(Clone, Debug)]
struct SimArgs {
    scenario: Scenario,
    compare_order: CompareOrder,
    warmup_secs: u64,
    autotune: bool,
    autotune_telemetry_caps: Vec<usize>,
    autotune_critical_caps: Vec<usize>,
    repeats: usize,
    output: OutputFormat,
    output_path: Option<String>,
    server_addr: SocketAddr,
    proxy_addr: SocketAddr,
    metrics_addr: SocketAddr,
    clients: usize,
    tick_hz: u64,
    duration_secs: u64,
    telemetry_per_tick: usize,
    max_packets_per_tick: usize,
    jitter_ms: u64,
    drop_rate: f64,
    proxy_workers: usize,
    proxy_batch_size: usize,
    proxy_queue_capacity: usize,
    proxy_telemetry_queue_capacity: usize,
    proxy_critical_queue_capacity: usize,
    proxy_downstream_telemetry_queue_capacity: Option<usize>,
    proxy_downstream_critical_queue_capacity: Option<usize>,
    proxy_critical_overflow_policy: CriticalOverflowPolicy,
    proxy_critical_block_timeout_millis: u64,
    proxy_downstream_telemetry_ttl_millis: u64,
    proxy_downstream_critical_ttl_millis: u64,
}

#[derive(Debug, Default, Clone)]
struct ServerStats {
    assigned_matches: u64,
    packets_critical: u64,
    packets_telemetry: u64,
    packets_other: u64,
    snapshots_sent: u64,
}

#[derive(Debug, Default, Clone)]
struct TrialMetrics {
    matched_clients: usize,
    sent_critical: u64,
    sent_telemetry: u64,
    recv_snapshots: u64,
    out_dropped: u64,
    in_dropped: u64,
    control_lag_avg: f64,
    control_lag_p50: f64,
    control_lag_p99: f64,
}

#[derive(Debug, Default, Clone)]
struct TrialResult {
    metrics: TrialMetrics,
    server: ServerStats,
}

#[derive(Debug, Clone, Default)]
struct RunRecord {
    repeat: usize,
    direct: Option<TrialResult>,
    proxied: Option<TrialResult>,
}

#[derive(Debug, Clone, Copy)]
struct SummaryStats {
    mean: f64,
    median: f64,
    p95: f64,
    p99: f64,
    min: f64,
    max: f64,
}

#[derive(Debug, Clone)]
struct AutotuneCandidateResult {
    queue_capacity: usize,
    telemetry_queue_capacity: usize,
    critical_queue_capacity: usize,
    score: f64,
    summary: DeltaSummary,
}

#[derive(Debug, Clone)]
struct AutotuneReport {
    candidates: Vec<AutotuneCandidateResult>,
    best_index: usize,
    best_runs: Vec<RunRecord>,
    best_stable_index: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct CarState {
    pos: f32,
    vel: f32,
    last_ack_seq: u32,
}

#[derive(Debug)]
struct Matchmaker {
    next_match_id: u32,
    waiting: VecDeque<SocketAddr>,
    waiting_set: HashSet<SocketAddr>,
    match_of: HashMap<SocketAddr, u32>,
}

impl Matchmaker {
    fn new() -> Self {
        Self {
            next_match_id: 1,
            waiting: VecDeque::new(),
            waiting_set: HashSet::new(),
            match_of: HashMap::new(),
        }
    }

    fn on_join(&mut self, addr: SocketAddr) {
        if self.match_of.contains_key(&addr) || self.waiting_set.contains(&addr) {
            return;
        }
        self.waiting.push_back(addr);
        self.waiting_set.insert(addr);
    }

    fn assign_pairs(&mut self) -> Vec<(SocketAddr, SocketAddr, u32)> {
        let mut out = Vec::new();
        loop {
            let Some(a) = self.waiting.pop_front() else {
                break;
            };
            let Some(b) = self.waiting.pop_front() else {
                self.waiting.push_front(a);
                break;
            };
            self.waiting_set.remove(&a);
            self.waiting_set.remove(&b);

            let id = self.next_match_id;
            self.next_match_id = self.next_match_id.saturating_add(1);
            self.match_of.insert(a, id);
            self.match_of.insert(b, id);
            out.push((a, b, id));
        }
        out
    }
}

#[derive(Debug)]
struct ScheduledPacket {
    at: Instant,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct LagInjector {
    jitter_ms: u64,
    drop_rate: f64,
    rng: SimpleRng,
}

impl LagInjector {
    fn new(jitter_ms: u64, drop_rate: f64, seed: u64) -> Self {
        Self {
            jitter_ms,
            drop_rate: drop_rate.clamp(0.0, 1.0),
            rng: SimpleRng::new(seed),
        }
    }

    fn should_drop(&mut self) -> bool {
        self.rng.next_f64() < self.drop_rate
    }

    fn delay(&mut self) -> Duration {
        if self.jitter_ms == 0 {
            return Duration::ZERO;
        }
        Duration::from_millis(self.rng.next_u64() % (self.jitter_ms + 1))
    }
}

#[derive(Debug)]
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        let seed = if seed == 0 {
            0x19E3_93D9_5AFE_C123
        } else {
            seed
        };
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_f64(&mut self) -> f64 {
        (self.next_u64() as f64) / (u64::MAX as f64)
    }
}

#[derive(Debug)]
struct ClientSim {
    id: u32,
    socket: UdpSocket,
    seq: u32,
    joined: bool,
    matched: bool,
    out_lag: LagInjector,
    in_lag: LagInjector,
    out_queue: VecDeque<ScheduledPacket>,
    in_queue: VecDeque<ScheduledPacket>,
    control_lag_samples: Vec<f64>,
    sent_critical: u64,
    sent_telemetry: u64,
    recv_snapshots: u64,
    out_dropped: u64,
    in_dropped: u64,
}

impl ClientSim {
    fn new(id: u32, jitter_ms: u64, drop_rate: f64, seed: u64) -> Result<Self, String> {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .map_err(|err| format!("bind client socket failed: {err}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|err| format!("set nonblocking failed: {err}"))?;
        Ok(Self {
            id,
            socket,
            seq: 0,
            joined: false,
            matched: false,
            out_lag: LagInjector::new(jitter_ms, drop_rate, seed ^ 0xA1A1_A1A1_1111_1111),
            in_lag: LagInjector::new(jitter_ms, drop_rate, seed ^ 0xB2B2_B2B2_2222_2222),
            out_queue: VecDeque::new(),
            in_queue: VecDeque::new(),
            control_lag_samples: Vec::new(),
            sent_critical: 0,
            sent_telemetry: 0,
            recv_snapshots: 0,
            out_dropped: 0,
            in_dropped: 0,
        })
    }
}

fn main() -> Result<(), String> {
    let args = parse_args()?;
    let rendered = if args.autotune {
        let report = run_autotune(&args)?;
        match args.output {
            OutputFormat::Text => render_autotune_text(&args, &report),
            OutputFormat::Json => render_autotune_json(&args, &report),
            OutputFormat::Csv => render_autotune_csv(&args, &report),
        }
    } else {
        let runs = execute_runs(&args)?;
        match args.output {
            OutputFormat::Text => render_text(&args, &runs),
            OutputFormat::Json => render_json(&args, &runs),
            OutputFormat::Csv => render_csv(&args, &runs),
        }
    };

    if let Some(path) = &args.output_path {
        fs::write(path, rendered.as_bytes())
            .map_err(|err| format!("failed to write --output-path '{path}': {err}"))?;
        println!("nx_eos_sim wrote output to {path}");
    } else {
        print!("{rendered}");
    }

    Ok(())
}

fn run_autotune(args: &SimArgs) -> Result<AutotuneReport, String> {
    if args.scenario != Scenario::Compare {
        return Err("--autotune=true requires --scenario=compare".to_string());
    }
    if args.autotune_telemetry_caps.is_empty() || args.autotune_critical_caps.is_empty() {
        return Err(
            "--autotune requires non-empty --autotune-telemetry-caps and --autotune-critical-caps"
                .to_string(),
        );
    }

    let mut candidates = Vec::<AutotuneCandidateResult>::new();
    let mut best_index = 0usize;
    let mut best_score = f64::NEG_INFINITY;
    let mut best_runs = Vec::<RunRecord>::new();
    let mut best_stable_index = 0usize;
    let mut best_stable_set = false;

    for &telemetry_cap in &args.autotune_telemetry_caps {
        for &critical_cap in &args.autotune_critical_caps {
            let mut tuned = args.clone();
            tuned.proxy_telemetry_queue_capacity = telemetry_cap;
            tuned.proxy_critical_queue_capacity = critical_cap;
            tuned.proxy_queue_capacity = args
                .proxy_queue_capacity
                .max(telemetry_cap.saturating_add(critical_cap));

            let runs = execute_runs(&tuned)?;
            let summary = summarize_deltas(&runs).ok_or_else(|| {
                "autotune could not compute summary (no comparable runs)".to_string()
            })?;
            let score = score_summary(&summary);
            let candidate_index = candidates.len();

            if score > best_score {
                best_score = score;
                best_index = candidate_index;
                best_runs = runs.clone();
            }

            candidates.push(AutotuneCandidateResult {
                queue_capacity: tuned.proxy_queue_capacity,
                telemetry_queue_capacity: telemetry_cap,
                critical_queue_capacity: critical_cap,
                score,
                summary,
            });

            if !best_stable_set
                || is_stable_better(
                    &candidates[candidate_index].summary,
                    candidates[candidate_index].score,
                    &candidates[best_stable_index].summary,
                    candidates[best_stable_index].score,
                )
            {
                best_stable_set = true;
                best_stable_index = candidate_index;
            }
        }
    }

    if candidates.is_empty() {
        return Err("autotune produced zero candidates".to_string());
    }
    if !best_stable_set {
        best_stable_index = best_index;
    }

    Ok(AutotuneReport {
        candidates,
        best_index,
        best_runs,
        best_stable_index,
    })
}

fn execute_runs(args: &SimArgs) -> Result<Vec<RunRecord>, String> {
    let mut out = Vec::with_capacity(args.repeats);
    for repeat in 0..args.repeats {
        match args.scenario {
            Scenario::Direct => {
                let direct = run_trial(args, false)?;
                out.push(RunRecord {
                    repeat: repeat + 1,
                    direct: Some(direct),
                    proxied: None,
                });
            }
            Scenario::Proxied => {
                let proxied = run_trial(args, true)?;
                out.push(RunRecord {
                    repeat: repeat + 1,
                    direct: None,
                    proxied: Some(proxied),
                });
            }
            Scenario::Compare => {
                let direct_first = match args.compare_order {
                    CompareOrder::DirectFirst => true,
                    CompareOrder::ProxiedFirst => false,
                    CompareOrder::Alternate => repeat % 2 == 0,
                };
                let (direct, proxied) = if direct_first {
                    (run_trial(args, false)?, run_trial(args, true)?)
                } else {
                    let proxied = run_trial(args, true)?;
                    let direct = run_trial(args, false)?;
                    (direct, proxied)
                };
                out.push(RunRecord {
                    repeat: repeat + 1,
                    direct: Some(direct),
                    proxied: Some(proxied),
                });
            }
        }
    }
    Ok(out)
}

fn render_text(args: &SimArgs, runs: &[RunRecord]) -> String {
    let mut out = String::new();
    for run in runs {
        match (run.direct.as_ref(), run.proxied.as_ref()) {
            (Some(direct), Some(proxied)) => {
                out.push_str(&format!("run={}\n", run.repeat));
                out.push_str(&format!("{}\n", format_result_line("direct", direct)));
                out.push_str(&format!("{}\n", format_result_line("proxied", proxied)));
                out.push_str(&format!(
                    "delta control_lag_avg={:.3} p50={:.3} p99={:.3} matched={} -> {} snapshots={} -> {}\n\n",
                    direct.metrics.control_lag_avg - proxied.metrics.control_lag_avg,
                    direct.metrics.control_lag_p50 - proxied.metrics.control_lag_p50,
                    direct.metrics.control_lag_p99 - proxied.metrics.control_lag_p99,
                    direct.metrics.matched_clients,
                    proxied.metrics.matched_clients,
                    direct.metrics.recv_snapshots,
                    proxied.metrics.recv_snapshots
                ));
            }
            (Some(direct), None) => {
                out.push_str(&format!(
                    "run={}\n{}\n\n",
                    run.repeat,
                    format_result_line("direct", direct)
                ));
            }
            (None, Some(proxied)) => {
                out.push_str(&format!(
                    "run={}\n{}\n\n",
                    run.repeat,
                    format_result_line("proxied", proxied)
                ));
            }
            (None, None) => {}
        }
    }

    if let Some(summary) = summarize_deltas(runs) {
        out.push_str("summary\n");
        out.push_str(&format_summary_line(
            "delta_control_lag_avg",
            summary.delta_control_lag_avg,
            summary.positive_lag_avg,
            summary.total_runs,
        ));
        out.push('\n');
        out.push_str(&format_summary_line(
            "delta_control_lag_p50",
            summary.delta_control_lag_p50,
            summary.positive_lag_p50,
            summary.total_runs,
        ));
        out.push('\n');
        out.push_str(&format_summary_line(
            "delta_control_lag_p99",
            summary.delta_control_lag_p99,
            summary.positive_lag_p99,
            summary.total_runs,
        ));
        out.push('\n');
        out.push_str(&format_summary_line(
            "delta_server_critical_direct_minus_proxied",
            summary.delta_server_critical_direct_minus_proxied,
            summary.positive_server_critical_direct_minus_proxied,
            summary.total_runs,
        ));
        out.push('\n');
        out.push_str(&format_summary_line(
            "delta_server_critical_proxied_minus_direct",
            summary.delta_server_critical_proxied_minus_direct,
            summary.positive_server_critical_proxied_minus_direct,
            summary.total_runs,
        ));
        out.push('\n');
        out.push_str(&format_summary_line(
            "lag_avg_improvement_pct",
            summary.lag_avg_improvement_pct,
            summary.positive_lag_avg_improvement_pct,
            summary.total_runs,
        ));
        out.push('\n');
        out.push_str(&format_summary_line(
            "lag_p99_improvement_pct",
            summary.lag_p99_improvement_pct,
            summary.positive_lag_p99_improvement_pct,
            summary.total_runs,
        ));
        out.push('\n');
    } else if args.scenario == Scenario::Compare {
        out.push_str("summary unavailable: no comparable runs\n");
    }

    out
}

fn render_csv(_args: &SimArgs, runs: &[RunRecord]) -> String {
    let mut out = String::new();
    out.push_str("repeat,direct_control_lag_avg,direct_control_lag_p50,direct_control_lag_p99,direct_matched,direct_snapshots,direct_server_crit,proxied_control_lag_avg,proxied_control_lag_p50,proxied_control_lag_p99,proxied_matched,proxied_snapshots,proxied_server_crit,delta_control_lag_avg,delta_control_lag_p50,delta_control_lag_p99,delta_matched,delta_snapshots,delta_server_crit\n");
    for run in runs {
        let direct = run.direct.as_ref();
        let proxied = run.proxied.as_ref();
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            run.repeat,
            opt_fmt_f64(direct.map(|d| d.metrics.control_lag_avg)),
            opt_fmt_f64(direct.map(|d| d.metrics.control_lag_p50)),
            opt_fmt_f64(direct.map(|d| d.metrics.control_lag_p99)),
            opt_fmt_usize(direct.map(|d| d.metrics.matched_clients)),
            opt_fmt_u64(direct.map(|d| d.metrics.recv_snapshots)),
            opt_fmt_u64(direct.map(|d| d.server.packets_critical)),
            opt_fmt_f64(proxied.map(|p| p.metrics.control_lag_avg)),
            opt_fmt_f64(proxied.map(|p| p.metrics.control_lag_p50)),
            opt_fmt_f64(proxied.map(|p| p.metrics.control_lag_p99)),
            opt_fmt_usize(proxied.map(|p| p.metrics.matched_clients)),
            opt_fmt_u64(proxied.map(|p| p.metrics.recv_snapshots)),
            opt_fmt_u64(proxied.map(|p| p.server.packets_critical)),
            opt_fmt_f64(delta_for(run).map(|d| d.control_lag_avg)),
            opt_fmt_f64(delta_for(run).map(|d| d.control_lag_p50)),
            opt_fmt_f64(delta_for(run).map(|d| d.control_lag_p99)),
            opt_fmt_i64(delta_for(run).map(|d| d.matched)),
            opt_fmt_i64(delta_for(run).map(|d| d.snapshots)),
            opt_fmt_i64(delta_for(run).map(|d| d.server_critical)),
        ));
    }

    if let Some(summary) = summarize_deltas(runs) {
        out.push('\n');
        out.push_str("summary_metric,mean,median,p95,p99,min,max,positive_runs,total_runs\n");
        out.push_str(&format_summary_csv_line(
            "delta_control_lag_avg",
            summary.delta_control_lag_avg,
            summary.positive_lag_avg,
            summary.total_runs,
        ));
        out.push('\n');
        out.push_str(&format_summary_csv_line(
            "delta_control_lag_p50",
            summary.delta_control_lag_p50,
            summary.positive_lag_p50,
            summary.total_runs,
        ));
        out.push('\n');
        out.push_str(&format_summary_csv_line(
            "delta_control_lag_p99",
            summary.delta_control_lag_p99,
            summary.positive_lag_p99,
            summary.total_runs,
        ));
        out.push('\n');
        out.push_str(&format_summary_csv_line(
            "delta_server_critical_direct_minus_proxied",
            summary.delta_server_critical_direct_minus_proxied,
            summary.positive_server_critical_direct_minus_proxied,
            summary.total_runs,
        ));
        out.push('\n');
        out.push_str(&format_summary_csv_line(
            "delta_server_critical_proxied_minus_direct",
            summary.delta_server_critical_proxied_minus_direct,
            summary.positive_server_critical_proxied_minus_direct,
            summary.total_runs,
        ));
        out.push('\n');
        out.push_str(&format_summary_csv_line(
            "lag_avg_improvement_pct",
            summary.lag_avg_improvement_pct,
            summary.positive_lag_avg_improvement_pct,
            summary.total_runs,
        ));
        out.push('\n');
        out.push_str(&format_summary_csv_line(
            "lag_p99_improvement_pct",
            summary.lag_p99_improvement_pct,
            summary.positive_lag_p99_improvement_pct,
            summary.total_runs,
        ));
        out.push('\n');
    }

    out
}

fn render_json(args: &SimArgs, runs: &[RunRecord]) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!(
        "\"scenario\":\"{}\",\"compare_order\":\"{}\",\"warmup_secs\":{},\"repeats\":{},\"output\":\"{}\",\"proxy_workers\":{},\"proxy_batch_size\":{},\"runs\":[",
        scenario_label(args.scenario),
        compare_order_label(args.compare_order),
        args.warmup_secs,
        args.repeats,
        output_label(args.output),
        args.proxy_workers,
        args.proxy_batch_size,
    ));

    for (idx, run) in runs.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        out.push_str(&format!("\"repeat\":{}", run.repeat));
        if let Some(d) = &run.direct {
            out.push_str(",\"direct\":");
            append_result_json(&mut out, d);
        }
        if let Some(p) = &run.proxied {
            out.push_str(",\"proxied\":");
            append_result_json(&mut out, p);
        }
        if let Some(delta) = delta_for(run) {
            out.push_str(&format!(
                ",\"delta\":{{\"control_lag_avg\":{:.6},\"control_lag_p50\":{:.6},\"control_lag_p99\":{:.6},\"matched\":{},\"snapshots\":{},\"server_critical\":{}}}",
                delta.control_lag_avg,
                delta.control_lag_p50,
                delta.control_lag_p99,
                delta.matched,
                delta.snapshots,
                delta.server_critical
            ));
        }
        out.push('}');
    }
    out.push(']');

    if let Some(summary) = summarize_deltas(runs) {
        out.push_str(",\"summary\":{");
        append_summary_json(
            &mut out,
            "delta_control_lag_avg",
            summary.delta_control_lag_avg,
            summary.positive_lag_avg,
            summary.total_runs,
            false,
        );
        append_summary_json(
            &mut out,
            "delta_control_lag_p50",
            summary.delta_control_lag_p50,
            summary.positive_lag_p50,
            summary.total_runs,
            true,
        );
        append_summary_json(
            &mut out,
            "delta_control_lag_p99",
            summary.delta_control_lag_p99,
            summary.positive_lag_p99,
            summary.total_runs,
            true,
        );
        append_summary_json(
            &mut out,
            "delta_server_critical_direct_minus_proxied",
            summary.delta_server_critical_direct_minus_proxied,
            summary.positive_server_critical_direct_minus_proxied,
            summary.total_runs,
            true,
        );
        append_summary_json(
            &mut out,
            "delta_server_critical_proxied_minus_direct",
            summary.delta_server_critical_proxied_minus_direct,
            summary.positive_server_critical_proxied_minus_direct,
            summary.total_runs,
            true,
        );
        append_summary_json(
            &mut out,
            "lag_avg_improvement_pct",
            summary.lag_avg_improvement_pct,
            summary.positive_lag_avg_improvement_pct,
            summary.total_runs,
            true,
        );
        append_summary_json(
            &mut out,
            "lag_p99_improvement_pct",
            summary.lag_p99_improvement_pct,
            summary.positive_lag_p99_improvement_pct,
            summary.total_runs,
            true,
        );
        out.push('}');
    }
    out.push('}');
    out
}

fn render_autotune_text(args: &SimArgs, report: &AutotuneReport) -> String {
    let mut ranked = report.candidates.clone();
    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut out = String::new();
    out.push_str("autotune\n");
    out.push_str(&format!(
        "tested_candidates={} repeats_per_candidate={} compare_order={} warmup_secs={}\n",
        report.candidates.len(),
        args.repeats,
        compare_order_label(args.compare_order),
        args.warmup_secs
    ));
    for (idx, c) in ranked.iter().enumerate() {
        out.push_str(&format!(
            "rank={} score={:.3} queue={} telemetry_queue={} critical_queue={} lag_avg_mean={:.3} lag_p99_mean={:.3} lag_avg_positive={}/{} lag_p99_positive={}/{}\n",
            idx + 1,
            c.score,
            c.queue_capacity,
            c.telemetry_queue_capacity,
            c.critical_queue_capacity,
            c.summary.delta_control_lag_avg.mean,
            c.summary.delta_control_lag_p99.mean,
            c.summary.positive_lag_avg,
            c.summary.total_runs,
            c.summary.positive_lag_p99,
            c.summary.total_runs
        ));
    }
    out.push('\n');
    let best = &report.candidates[report.best_index];
    out.push_str(&format!(
        "best_config queue={} telemetry_queue={} critical_queue={} score={:.3}\n",
        best.queue_capacity,
        best.telemetry_queue_capacity,
        best.critical_queue_capacity,
        best.score
    ));
    let best_stable = &report.candidates[report.best_stable_index];
    out.push_str(&format!(
        "best_stable_config queue={} telemetry_queue={} critical_queue={} score={:.3} p99_min={:.3} p99_pos={}/{}\n",
        best_stable.queue_capacity,
        best_stable.telemetry_queue_capacity,
        best_stable.critical_queue_capacity,
        best_stable.score,
        best_stable.summary.delta_control_lag_p99.min,
        best_stable.summary.positive_lag_p99,
        best_stable.summary.total_runs,
    ));
    out.push_str(&format!(
        "best_stable_flags --proxy-queue-capacity={} --proxy-telemetry-queue-capacity={} --proxy-critical-queue-capacity={}\n",
        best_stable.queue_capacity,
        best_stable.telemetry_queue_capacity,
        best_stable.critical_queue_capacity,
    ));

    let mut best_args = args.clone();
    best_args.proxy_queue_capacity = best.queue_capacity;
    best_args.proxy_telemetry_queue_capacity = best.telemetry_queue_capacity;
    best_args.proxy_critical_queue_capacity = best.critical_queue_capacity;
    out.push('\n');
    out.push_str(&render_text(&best_args, &report.best_runs));
    out
}

fn render_autotune_csv(args: &SimArgs, report: &AutotuneReport) -> String {
    let mut out = String::new();
    out.push_str("candidate,score,queue_capacity,telemetry_queue_capacity,critical_queue_capacity,lag_avg_mean,lag_avg_median,lag_avg_positive,lag_p99_mean,lag_p99_median,lag_p99_positive,lag_avg_improvement_pct_mean,lag_p99_improvement_pct_mean,server_critical_proxied_minus_direct_mean\n");
    for (idx, c) in report.candidates.iter().enumerate() {
        out.push_str(&format!(
            "{},{:.6},{},{},{},{:.6},{:.6},{},{:.6},{:.6},{},{:.6},{:.6},{:.6}\n",
            idx + 1,
            c.score,
            c.queue_capacity,
            c.telemetry_queue_capacity,
            c.critical_queue_capacity,
            c.summary.delta_control_lag_avg.mean,
            c.summary.delta_control_lag_avg.median,
            c.summary.positive_lag_avg,
            c.summary.delta_control_lag_p99.mean,
            c.summary.delta_control_lag_p99.median,
            c.summary.positive_lag_p99,
            c.summary.lag_avg_improvement_pct.mean,
            c.summary.lag_p99_improvement_pct.mean,
            c.summary.delta_server_critical_proxied_minus_direct.mean,
        ));
    }
    let best = &report.candidates[report.best_index];
    out.push('\n');
    out.push_str(&format!(
        "best,{:.6},{},{},{},{:.6},{:.6},{},{:.6},{:.6},{},{:.6},{:.6},{:.6}\n",
        best.score,
        best.queue_capacity,
        best.telemetry_queue_capacity,
        best.critical_queue_capacity,
        best.summary.delta_control_lag_avg.mean,
        best.summary.delta_control_lag_avg.median,
        best.summary.positive_lag_avg,
        best.summary.delta_control_lag_p99.mean,
        best.summary.delta_control_lag_p99.median,
        best.summary.positive_lag_p99,
        best.summary.lag_avg_improvement_pct.mean,
        best.summary.lag_p99_improvement_pct.mean,
        best.summary.delta_server_critical_proxied_minus_direct.mean,
    ));
    let best_stable = &report.candidates[report.best_stable_index];
    out.push_str(&format!(
        "best_stable,{:.6},{},{},{},{:.6},{:.6},{},{:.6},{:.6},{},{:.6},{:.6},{:.6}\n",
        best_stable.score,
        best_stable.queue_capacity,
        best_stable.telemetry_queue_capacity,
        best_stable.critical_queue_capacity,
        best_stable.summary.delta_control_lag_avg.mean,
        best_stable.summary.delta_control_lag_avg.median,
        best_stable.summary.positive_lag_avg,
        best_stable.summary.delta_control_lag_p99.mean,
        best_stable.summary.delta_control_lag_p99.median,
        best_stable.summary.positive_lag_p99,
        best_stable.summary.lag_avg_improvement_pct.mean,
        best_stable.summary.lag_p99_improvement_pct.mean,
        best_stable
            .summary
            .delta_server_critical_proxied_minus_direct
            .mean,
    ));
    out.push_str(&format!(
        "# repeats_per_candidate={},compare_order={},warmup_secs={}\n",
        args.repeats,
        compare_order_label(args.compare_order),
        args.warmup_secs
    ));
    out
}

fn render_autotune_json(args: &SimArgs, report: &AutotuneReport) -> String {
    let mut out = String::new();
    out.push_str("{\"mode\":\"autotune\"");
    out.push_str(&format!(
        ",\"scenario\":\"{}\",\"compare_order\":\"{}\",\"warmup_secs\":{},\"repeats_per_candidate\":{}",
        scenario_label(args.scenario),
        compare_order_label(args.compare_order),
        args.warmup_secs,
        args.repeats
    ));
    out.push_str(",\"candidates\":[");
    for (idx, c) in report.candidates.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        out.push_str(&format!(
            "\"queue_capacity\":{},\"telemetry_queue_capacity\":{},\"critical_queue_capacity\":{},\"score\":{:.6},\"summary\":{{",
            c.queue_capacity,
            c.telemetry_queue_capacity,
            c.critical_queue_capacity,
            c.score
        ));
        append_summary_json(
            &mut out,
            "delta_control_lag_avg",
            c.summary.delta_control_lag_avg,
            c.summary.positive_lag_avg,
            c.summary.total_runs,
            false,
        );
        append_summary_json(
            &mut out,
            "delta_control_lag_p99",
            c.summary.delta_control_lag_p99,
            c.summary.positive_lag_p99,
            c.summary.total_runs,
            true,
        );
        append_summary_json(
            &mut out,
            "lag_avg_improvement_pct",
            c.summary.lag_avg_improvement_pct,
            c.summary.positive_lag_avg_improvement_pct,
            c.summary.total_runs,
            true,
        );
        append_summary_json(
            &mut out,
            "lag_p99_improvement_pct",
            c.summary.lag_p99_improvement_pct,
            c.summary.positive_lag_p99_improvement_pct,
            c.summary.total_runs,
            true,
        );
        out.push_str("}}");
    }
    out.push(']');
    let best = &report.candidates[report.best_index];
    out.push_str(&format!(
        ",\"best_candidate\":{{\"queue_capacity\":{},\"telemetry_queue_capacity\":{},\"critical_queue_capacity\":{},\"score\":{:.6}}}",
        best.queue_capacity,
        best.telemetry_queue_capacity,
        best.critical_queue_capacity,
        best.score
    ));
    let best_stable = &report.candidates[report.best_stable_index];
    out.push_str(&format!(
        ",\"best_candidate_stable\":{{\"queue_capacity\":{},\"telemetry_queue_capacity\":{},\"critical_queue_capacity\":{},\"score\":{:.6}}}",
        best_stable.queue_capacity,
        best_stable.telemetry_queue_capacity,
        best_stable.critical_queue_capacity,
        best_stable.score
    ));
    out.push('}');
    out
}

fn run_trial(args: &SimArgs, use_proxy: bool) -> Result<TrialResult, String> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_handle = spawn_server(
        args.server_addr,
        args.max_packets_per_tick,
        args.tick_hz,
        shutdown.clone(),
    )?;

    let mut proxy_runtime = None::<Runtime>;
    let mut proxy_shutdown = None::<CancellationToken>;
    if use_proxy {
        let rt = Runtime::new().map_err(|err| format!("create runtime failed: {err}"))?;
        let token = CancellationToken::new();
        let child = token.clone();
        let cfg = proxy_config(args, args.proxy_addr, args.server_addr, args.metrics_addr);
        rt.spawn(async move {
            if let Err(err) = run_proxy(cfg, child).await {
                eprintln!("nx_eos_sim proxy worker error: {err}");
            }
        });
        proxy_runtime = Some(rt);
        proxy_shutdown = Some(token);
        thread::sleep(Duration::from_millis(200));
    }

    let target = if use_proxy {
        args.proxy_addr
    } else {
        args.server_addr
    };
    let metrics = run_clients(args, target)?;

    if let Some(token) = proxy_shutdown {
        token.cancel();
    }
    if let Some(rt) = proxy_runtime {
        rt.shutdown_timeout(Duration::from_millis(300));
    }

    shutdown.store(true, Ordering::Relaxed);
    let server = server_handle
        .join()
        .map_err(|_| "server thread panicked".to_string())?;

    Ok(TrialResult { metrics, server })
}

fn spawn_server(
    bind_addr: SocketAddr,
    max_packets_per_tick: usize,
    tick_hz: u64,
    shutdown: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<ServerStats>, String> {
    let socket = UdpSocket::bind(bind_addr)
        .map_err(|err| format!("bind server {bind_addr} failed: {err}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("server nonblocking failed: {err}"))?;
    let tick_sleep = Duration::from_micros(1_000_000 / tick_hz.max(1));

    let handle = thread::spawn(move || {
        let mut stats = ServerStats::default();
        let mut recv_buf = [0u8; 2048];
        let mut tick: u32 = 0;
        let mut matchmaker = Matchmaker::new();
        let mut cars: HashMap<SocketAddr, CarState> = HashMap::new();
        let mut ball_pos = 0.0f32;
        let mut ball_vel = 0.0f32;

        while !shutdown.load(Ordering::Relaxed) {
            let started = Instant::now();
            let mut processed = 0usize;
            while processed < max_packets_per_tick {
                match socket.recv_from(&mut recv_buf) {
                    Ok((len, peer)) => {
                        processed = processed.saturating_add(1);
                        let payload = match std::str::from_utf8(&recv_buf[..len]) {
                            Ok(v) => v,
                            Err(_) => {
                                stats.packets_other = stats.packets_other.saturating_add(1);
                                continue;
                            }
                        };

                        if payload.starts_with("JOIN ") {
                            matchmaker.on_join(peer);
                            cars.entry(peer).or_default();
                            continue;
                        }

                        if payload.starts_with("CRIT ") {
                            stats.packets_critical = stats.packets_critical.saturating_add(1);
                            // Treat any valid control-path traffic as an implicit join to reduce
                            // handshake loss sensitivity under overload (keeps comparisons stable).
                            matchmaker.on_join(peer);
                            let mut parts = payload.split_whitespace();
                            let _ = parts.next();
                            let _cid = parts.next();
                            let seq = parts
                                .next()
                                .and_then(|s| s.parse::<u32>().ok())
                                .unwrap_or(0);
                            let throttle = parts
                                .next()
                                .and_then(|v| v.parse::<f32>().ok())
                                .unwrap_or(0.0)
                                .clamp(-1.0, 1.0);
                            let car = cars.entry(peer).or_default();
                            car.vel = (car.vel + throttle * (25.0 / tick_hz.max(1) as f32)) * 0.985;
                            car.pos += car.vel;
                            car.last_ack_seq = seq;
                            continue;
                        }

                        if payload.starts_with("TELE:") {
                            stats.packets_telemetry = stats.packets_telemetry.saturating_add(1);
                            continue;
                        }

                        stats.packets_other = stats.packets_other.saturating_add(1);
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }

            for (a, b, match_id) in matchmaker.assign_pairs() {
                let _ = socket.send_to(format!("MATCH {match_id}").as_bytes(), a);
                let _ = socket.send_to(format!("MATCH {match_id}").as_bytes(), b);
                stats.assigned_matches = stats.assigned_matches.saturating_add(1);
            }

            tick = tick.saturating_add(1);
            let avg_car = if cars.is_empty() {
                0.0
            } else {
                cars.values().map(|c| c.pos).sum::<f32>() / cars.len() as f32
            };
            ball_vel = (ball_vel + (avg_car - ball_pos) * 0.05) * 0.992;
            ball_pos += ball_vel;

            for (peer, car) in &cars {
                if !matchmaker.match_of.contains_key(peer) {
                    continue;
                }
                let snap = format!(
                    "SNAP {tick} {} {:.4} {:.4}",
                    car.last_ack_seq, car.pos, ball_pos
                );
                if socket.send_to(snap.as_bytes(), peer).is_ok() {
                    stats.snapshots_sent = stats.snapshots_sent.saturating_add(1);
                }
            }

            let elapsed = started.elapsed();
            if elapsed < tick_sleep {
                thread::sleep(tick_sleep - elapsed);
            }
        }

        stats
    });
    Ok(handle)
}

fn run_clients(args: &SimArgs, target_addr: SocketAddr) -> Result<TrialMetrics, String> {
    let mut clients = Vec::<ClientSim>::with_capacity(args.clients);
    for i in 0..args.clients {
        clients.push(ClientSim::new(
            i as u32,
            args.jitter_ms,
            args.drop_rate,
            0x1000 + i as u64,
        )?);
    }

    let total_ticks = args.duration_secs.saturating_mul(args.tick_hz.max(1));
    let warmup_ticks = args.warmup_secs.saturating_mul(args.tick_hz.max(1));
    let tick_sleep = Duration::from_micros(1_000_000 / args.tick_hz.max(1));
    let mut recv_buf = [0u8; 2048];

    for tick_idx in 0..total_ticks {
        let started = Instant::now();
        for c in &mut clients {
            if !c.joined {
                queue_out(c, format!("JOIN {}", c.id).into_bytes());
                c.joined = true;
            }

            c.seq = c.seq.saturating_add(1);
            queue_out(c, format!("CRIT {} {} 1.0", c.id, c.seq).into_bytes());
            c.sent_critical = c.sent_critical.saturating_add(1);

            for n in 0..args.telemetry_per_tick {
                queue_out(c, format!("TELE:{}:{}", c.id, n).into_bytes());
                c.sent_telemetry = c.sent_telemetry.saturating_add(1);
            }

            flush_out(c, target_addr);
            recv_in(c, &mut recv_buf);
            process_in(c);
        }

        if warmup_ticks > 0 && tick_idx + 1 == warmup_ticks {
            reset_measurement_counters(&mut clients);
        }

        let elapsed = started.elapsed();
        if elapsed < tick_sleep {
            thread::sleep(tick_sleep - elapsed);
        }
    }

    // short drain
    let drain_deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < drain_deadline {
        for c in &mut clients {
            flush_out(c, target_addr);
            recv_in(c, &mut recv_buf);
            process_in(c);
        }
        thread::sleep(Duration::from_millis(3));
    }

    let mut all_lag = Vec::<f64>::new();
    let mut out_dropped = 0u64;
    let mut in_dropped = 0u64;
    let mut recv_snapshots = 0u64;
    let mut sent_critical = 0u64;
    let mut sent_telemetry = 0u64;
    let mut matched_clients = 0usize;

    for c in clients {
        if c.matched {
            matched_clients = matched_clients.saturating_add(1);
        }
        out_dropped = out_dropped.saturating_add(c.out_dropped);
        in_dropped = in_dropped.saturating_add(c.in_dropped);
        recv_snapshots = recv_snapshots.saturating_add(c.recv_snapshots);
        sent_critical = sent_critical.saturating_add(c.sent_critical);
        sent_telemetry = sent_telemetry.saturating_add(c.sent_telemetry);
        all_lag.extend(c.control_lag_samples);
    }

    all_lag.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let (avg, p50, p99) = if all_lag.is_empty() {
        (0.0, 0.0, 0.0)
    } else {
        let avg = all_lag.iter().sum::<f64>() / all_lag.len() as f64;
        let p50 = percentile(&all_lag, 0.50);
        let p99 = percentile(&all_lag, 0.99);
        (avg, p50, p99)
    };

    Ok(TrialMetrics {
        matched_clients,
        sent_critical,
        sent_telemetry,
        recv_snapshots,
        out_dropped,
        in_dropped,
        control_lag_avg: avg,
        control_lag_p50: p50,
        control_lag_p99: p99,
    })
}

fn queue_out(client: &mut ClientSim, bytes: Vec<u8>) {
    if client.out_lag.should_drop() {
        client.out_dropped = client.out_dropped.saturating_add(1);
        return;
    }
    client.out_queue.push_back(ScheduledPacket {
        at: Instant::now() + client.out_lag.delay(),
        bytes,
    });
}

fn flush_out(client: &mut ClientSim, target: SocketAddr) {
    let now = Instant::now();
    loop {
        let Some(pkt) = client.out_queue.front() else {
            break;
        };
        if pkt.at > now {
            break;
        }
        let pkt = client.out_queue.pop_front().expect("checked front");
        let _ = client.socket.send_to(&pkt.bytes, target);
    }
}

fn recv_in(client: &mut ClientSim, recv_buf: &mut [u8]) {
    loop {
        match client.socket.recv_from(recv_buf) {
            Ok((len, _)) => {
                if client.in_lag.should_drop() {
                    client.in_dropped = client.in_dropped.saturating_add(1);
                    continue;
                }
                client.in_queue.push_back(ScheduledPacket {
                    at: Instant::now() + client.in_lag.delay(),
                    bytes: recv_buf[..len].to_vec(),
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

fn process_in(client: &mut ClientSim) {
    let now = Instant::now();
    loop {
        let Some(pkt) = client.in_queue.front() else {
            break;
        };
        if pkt.at > now {
            break;
        }
        let pkt = client.in_queue.pop_front().expect("checked front");
        let msg = match std::str::from_utf8(&pkt.bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if msg.starts_with("MATCH ") {
            client.matched = true;
            continue;
        }

        if let Some(ack_seq) = parse_snap_ack_seq(msg) {
            client.recv_snapshots = client.recv_snapshots.saturating_add(1);
            let lag = client.seq.saturating_sub(ack_seq) as f64;
            client.control_lag_samples.push(lag);
        }
    }
}

fn reset_measurement_counters(clients: &mut [ClientSim]) {
    for c in clients {
        c.sent_critical = 0;
        c.sent_telemetry = 0;
        c.recv_snapshots = 0;
        c.out_dropped = 0;
        c.in_dropped = 0;
        c.control_lag_samples.clear();
    }
}

fn parse_snap_ack_seq(msg: &str) -> Option<u32> {
    // SNAP <tick> <ack_seq> <car_pos> <ball_pos>
    let mut p = msg.split_whitespace();
    if p.next()? != "SNAP" {
        return None;
    }
    let _tick = p.next()?;
    p.next()?.parse::<u32>().ok()
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn proxy_config(
    args: &SimArgs,
    listen_addr: SocketAddr,
    upstream_addr: SocketAddr,
    metrics_addr: SocketAddr,
) -> ProxyConfig {
    ProxyConfig {
        proxy: ProxySection {
            listen_addr,
            upstream_addr,
            worker_count: args.proxy_workers,
            reuse_port: true,
            pin_workers: false,
            batch_size: args.proxy_batch_size,
            max_sessions: 4096,
            min_datagram_bytes: 1,
            max_datagram_bytes: 1400,
            drop_udp_fragments: true,
            queue_capacity: args.proxy_queue_capacity,
            telemetry_queue_capacity: Some(args.proxy_telemetry_queue_capacity),
            critical_queue_capacity: Some(args.proxy_critical_queue_capacity),
            downstream_telemetry_queue_capacity: args.proxy_downstream_telemetry_queue_capacity,
            downstream_critical_queue_capacity: args.proxy_downstream_critical_queue_capacity,
            critical_overflow_policy: args.proxy_critical_overflow_policy,
            critical_block_timeout_millis: args.proxy_critical_block_timeout_millis,
            downstream_telemetry_ttl_millis: args.proxy_downstream_telemetry_ttl_millis,
            downstream_critical_ttl_millis: args.proxy_downstream_critical_ttl_millis,
            telemetry_prefixes: vec!["TELE:".to_string()],
            telemetry_prefixes_upstream: Vec::new(),
            telemetry_prefixes_downstream: Vec::new(),
        },
        rate_limit: RateLimitSection {
            per_ip_packets_per_second: 500_000.0,
            per_ip_burst_packets: 500_000.0,
            per_ip_bytes_per_second: 500_000_000.0,
            per_ip_burst_bytes: 500_000_000.0,
            global_packets_per_second: 500_000.0,
            global_burst_packets: 500_000.0,
            global_bytes_per_second: 500_000_000.0,
            global_burst_bytes: 500_000_000.0,
            subnet_enabled: false,
            subnet_ipv4_prefix: 24,
            subnet_ipv6_prefix: 64,
            subnet_packets_per_second: 100_000.0,
            subnet_burst_packets: 100_000.0,
            subnet_bytes_per_second: 100_000_000.0,
            subnet_burst_bytes: 100_000_000.0,
            max_ip_buckets: 16_384,
            max_subnet_buckets: 2_048,
            idle_timeout_secs: 120,
        },
        packet_validation: PacketValidationSection {
            enabled: false,
            strict_mode: true,
            require_checksum: false,
            strip_checksum_header: true,
        },
        anomaly: AnomalySection {
            enabled: false,
            ..AnomalySection::default()
        },
        mmr: MmrSection {
            enabled: false,
            ..MmrSection::default()
        },
        flood_sim: FloodSimSection::default(),
        cookie: CookieSection {
            enabled: false,
            mode: CookieMode::Compat,
            ..CookieSection::default()
        },
        metrics: MetricsSection {
            enabled: false,
            listen_addr: metrics_addr,
        },
    }
}

#[derive(Debug, Clone, Copy)]
struct DeltaMetrics {
    control_lag_avg: f64,
    control_lag_p50: f64,
    control_lag_p99: f64,
    matched: i64,
    snapshots: i64,
    server_critical: i64,
}

#[derive(Debug, Clone, Copy)]
struct DeltaSummary {
    total_runs: usize,
    delta_control_lag_avg: SummaryStats,
    delta_control_lag_p50: SummaryStats,
    delta_control_lag_p99: SummaryStats,
    delta_server_critical_direct_minus_proxied: SummaryStats,
    delta_server_critical_proxied_minus_direct: SummaryStats,
    lag_avg_improvement_pct: SummaryStats,
    lag_p99_improvement_pct: SummaryStats,
    positive_lag_avg: usize,
    positive_lag_p50: usize,
    positive_lag_p99: usize,
    positive_server_critical_direct_minus_proxied: usize,
    positive_server_critical_proxied_minus_direct: usize,
    positive_lag_avg_improvement_pct: usize,
    positive_lag_p99_improvement_pct: usize,
}

fn scenario_label(s: Scenario) -> &'static str {
    match s {
        Scenario::Direct => "direct",
        Scenario::Proxied => "proxied",
        Scenario::Compare => "compare",
    }
}

fn output_label(o: OutputFormat) -> &'static str {
    match o {
        OutputFormat::Text => "text",
        OutputFormat::Json => "json",
        OutputFormat::Csv => "csv",
    }
}

fn compare_order_label(o: CompareOrder) -> &'static str {
    match o {
        CompareOrder::DirectFirst => "direct-first",
        CompareOrder::ProxiedFirst => "proxied-first",
        CompareOrder::Alternate => "alternate",
    }
}

fn format_result_line(name: &str, result: &TrialResult) -> String {
    format!(
        "{name}: matched_clients={} control_lag_avg={:.3} p50={:.3} p99={:.3} recv_snapshots={} sent_critical={} sent_telemetry={} out_drop={} in_drop={} server_matches={} server_crit={} server_tele={} server_snapshots={}",
        result.metrics.matched_clients,
        result.metrics.control_lag_avg,
        result.metrics.control_lag_p50,
        result.metrics.control_lag_p99,
        result.metrics.recv_snapshots,
        result.metrics.sent_critical,
        result.metrics.sent_telemetry,
        result.metrics.out_dropped,
        result.metrics.in_dropped,
        result.server.assigned_matches,
        result.server.packets_critical,
        result.server.packets_telemetry,
        result.server.snapshots_sent
    )
}

fn delta_for(run: &RunRecord) -> Option<DeltaMetrics> {
    let direct = run.direct.as_ref()?;
    let proxied = run.proxied.as_ref()?;
    Some(DeltaMetrics {
        control_lag_avg: direct.metrics.control_lag_avg - proxied.metrics.control_lag_avg,
        control_lag_p50: direct.metrics.control_lag_p50 - proxied.metrics.control_lag_p50,
        control_lag_p99: direct.metrics.control_lag_p99 - proxied.metrics.control_lag_p99,
        matched: direct.metrics.matched_clients as i64 - proxied.metrics.matched_clients as i64,
        snapshots: direct.metrics.recv_snapshots as i64 - proxied.metrics.recv_snapshots as i64,
        server_critical: direct.server.packets_critical as i64
            - proxied.server.packets_critical as i64,
    })
}

fn summarize_deltas(runs: &[RunRecord]) -> Option<DeltaSummary> {
    let mut lag_avg = Vec::<f64>::new();
    let mut lag_p50 = Vec::<f64>::new();
    let mut lag_p99 = Vec::<f64>::new();
    let mut server_critical_direct_minus_proxied = Vec::<f64>::new();
    let mut server_critical_proxied_minus_direct = Vec::<f64>::new();
    let mut lag_avg_improvement_pct = Vec::<f64>::new();
    let mut lag_p99_improvement_pct = Vec::<f64>::new();
    let mut positive_lag_avg = 0usize;
    let mut positive_lag_p50 = 0usize;
    let mut positive_lag_p99 = 0usize;
    let mut positive_server_critical_direct_minus_proxied = 0usize;
    let mut positive_server_critical_proxied_minus_direct = 0usize;
    let mut positive_lag_avg_improvement_pct = 0usize;
    let mut positive_lag_p99_improvement_pct = 0usize;

    for run in runs {
        let Some(delta) = delta_for(run) else {
            continue;
        };
        let direct = run
            .direct
            .as_ref()
            .expect("delta exists only when direct exists");
        let proxied = run
            .proxied
            .as_ref()
            .expect("delta exists only when proxied exists");

        lag_avg.push(delta.control_lag_avg);
        lag_p50.push(delta.control_lag_p50);
        lag_p99.push(delta.control_lag_p99);
        server_critical_direct_minus_proxied.push(delta.server_critical as f64);
        let proxied_minus_direct =
            (proxied.server.packets_critical as i64 - direct.server.packets_critical as i64) as f64;
        server_critical_proxied_minus_direct.push(proxied_minus_direct);
        let avg_pct = if direct.metrics.control_lag_avg.abs() > f64::EPSILON {
            (delta.control_lag_avg / direct.metrics.control_lag_avg) * 100.0
        } else {
            0.0
        };
        lag_avg_improvement_pct.push(avg_pct);
        if avg_pct > 0.0 {
            positive_lag_avg_improvement_pct = positive_lag_avg_improvement_pct.saturating_add(1);
        }
        let p99_pct = if direct.metrics.control_lag_p99.abs() > f64::EPSILON {
            (delta.control_lag_p99 / direct.metrics.control_lag_p99) * 100.0
        } else {
            0.0
        };
        lag_p99_improvement_pct.push(p99_pct);
        if p99_pct > 0.0 {
            positive_lag_p99_improvement_pct = positive_lag_p99_improvement_pct.saturating_add(1);
        }
        if delta.control_lag_avg > 0.0 {
            positive_lag_avg = positive_lag_avg.saturating_add(1);
        }
        if delta.control_lag_p50 > 0.0 {
            positive_lag_p50 = positive_lag_p50.saturating_add(1);
        }
        if delta.control_lag_p99 > 0.0 {
            positive_lag_p99 = positive_lag_p99.saturating_add(1);
        }
        if delta.server_critical > 0 {
            positive_server_critical_direct_minus_proxied =
                positive_server_critical_direct_minus_proxied.saturating_add(1);
        }
        if proxied_minus_direct > 0.0 {
            positive_server_critical_proxied_minus_direct =
                positive_server_critical_proxied_minus_direct.saturating_add(1);
        }
    }

    if lag_avg.is_empty() {
        return None;
    }

    Some(DeltaSummary {
        total_runs: lag_avg.len(),
        delta_control_lag_avg: summarize(&lag_avg),
        delta_control_lag_p50: summarize(&lag_p50),
        delta_control_lag_p99: summarize(&lag_p99),
        delta_server_critical_direct_minus_proxied: summarize(
            &server_critical_direct_minus_proxied,
        ),
        delta_server_critical_proxied_minus_direct: summarize(
            &server_critical_proxied_minus_direct,
        ),
        lag_avg_improvement_pct: summarize(&lag_avg_improvement_pct),
        lag_p99_improvement_pct: summarize(&lag_p99_improvement_pct),
        positive_lag_avg,
        positive_lag_p50,
        positive_lag_p99,
        positive_server_critical_direct_minus_proxied,
        positive_server_critical_proxied_minus_direct,
        positive_lag_avg_improvement_pct,
        positive_lag_p99_improvement_pct,
    })
}

fn summarize(samples: &[f64]) -> SummaryStats {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    SummaryStats {
        mean,
        median: percentile(&sorted, 0.50),
        p95: percentile(&sorted, 0.95),
        p99: percentile(&sorted, 0.99),
        min: *sorted.first().unwrap_or(&0.0),
        max: *sorted.last().unwrap_or(&0.0),
    }
}

fn score_summary(summary: &DeltaSummary) -> f64 {
    let total = summary.total_runs.max(1) as f64;
    let lag_avg_positive_ratio = summary.positive_lag_avg as f64 / total;
    let lag_p99_positive_ratio = summary.positive_lag_p99 as f64 / total;

    // Higher is better: improvement means +delta on direct-minus-proxied lag metrics.
    (summary.delta_control_lag_avg.mean * 1.5)
        + (summary.delta_control_lag_p99.mean * 0.3)
        + (lag_avg_positive_ratio * 25.0)
        + (lag_p99_positive_ratio * 30.0)
        + (summary.delta_server_critical_proxied_minus_direct.mean * 0.02)
        - (summary.delta_control_lag_p99.min.min(0.0).abs() * 0.2)
}

fn is_stable_better(
    candidate: &DeltaSummary,
    candidate_score: f64,
    current: &DeltaSummary,
    current_score: f64,
) -> bool {
    fn norm(v: f64) -> f64 {
        if v.is_nan() {
            f64::NEG_INFINITY
        } else {
            v
        }
    }

    let cand_p99_min = norm(candidate.delta_control_lag_p99.min);
    let cur_p99_min = norm(current.delta_control_lag_p99.min);
    if cand_p99_min != cur_p99_min {
        return cand_p99_min > cur_p99_min;
    }

    let cand_total = candidate.total_runs.max(1) as f64;
    let cur_total = current.total_runs.max(1) as f64;
    let cand_p99_pos = candidate.positive_lag_p99 as f64 / cand_total;
    let cur_p99_pos = current.positive_lag_p99 as f64 / cur_total;
    if cand_p99_pos != cur_p99_pos {
        return cand_p99_pos > cur_p99_pos;
    }

    let cand_p99_mean = norm(candidate.delta_control_lag_p99.mean);
    let cur_p99_mean = norm(current.delta_control_lag_p99.mean);
    if cand_p99_mean != cur_p99_mean {
        return cand_p99_mean > cur_p99_mean;
    }

    let cand_avg_mean = norm(candidate.delta_control_lag_avg.mean);
    let cur_avg_mean = norm(current.delta_control_lag_avg.mean);
    if cand_avg_mean != cur_avg_mean {
        return cand_avg_mean > cur_avg_mean;
    }

    norm(candidate_score) > norm(current_score)
}

fn format_summary_line(
    metric: &str,
    stats: SummaryStats,
    positive_runs: usize,
    total_runs: usize,
) -> String {
    format!(
        "{metric}: mean={:.3} median={:.3} p95={:.3} p99={:.3} min={:.3} max={:.3} positive={}/{}",
        stats.mean,
        stats.median,
        stats.p95,
        stats.p99,
        stats.min,
        stats.max,
        positive_runs,
        total_runs
    )
}

fn format_summary_csv_line(
    metric: &str,
    stats: SummaryStats,
    positive_runs: usize,
    total_runs: usize,
) -> String {
    format!(
        "{metric},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{}",
        stats.mean,
        stats.median,
        stats.p95,
        stats.p99,
        stats.min,
        stats.max,
        positive_runs,
        total_runs
    )
}

fn append_result_json(out: &mut String, result: &TrialResult) {
    out.push_str(&format!(
        "{{\"matched_clients\":{},\"control_lag_avg\":{:.6},\"control_lag_p50\":{:.6},\"control_lag_p99\":{:.6},\"recv_snapshots\":{},\"sent_critical\":{},\"sent_telemetry\":{},\"out_dropped\":{},\"in_dropped\":{},\"server_matches\":{},\"server_crit\":{},\"server_tele\":{},\"server_snapshots\":{}}}",
        result.metrics.matched_clients,
        result.metrics.control_lag_avg,
        result.metrics.control_lag_p50,
        result.metrics.control_lag_p99,
        result.metrics.recv_snapshots,
        result.metrics.sent_critical,
        result.metrics.sent_telemetry,
        result.metrics.out_dropped,
        result.metrics.in_dropped,
        result.server.assigned_matches,
        result.server.packets_critical,
        result.server.packets_telemetry,
        result.server.snapshots_sent
    ));
}

fn append_summary_json(
    out: &mut String,
    key: &str,
    stats: SummaryStats,
    positive_runs: usize,
    total_runs: usize,
    prepend_comma: bool,
) {
    if prepend_comma {
        out.push(',');
    }
    out.push_str(&format!(
        "\"{}\":{{\"mean\":{:.6},\"median\":{:.6},\"p95\":{:.6},\"p99\":{:.6},\"min\":{:.6},\"max\":{:.6},\"positive_runs\":{},\"total_runs\":{}}}",
        key,
        stats.mean,
        stats.median,
        stats.p95,
        stats.p99,
        stats.min,
        stats.max,
        positive_runs,
        total_runs
    ));
}

fn opt_fmt_f64(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.6}")).unwrap_or_default()
}

fn opt_fmt_usize(v: Option<usize>) -> String {
    v.map(|x| x.to_string()).unwrap_or_default()
}

fn opt_fmt_u64(v: Option<u64>) -> String {
    v.map(|x| x.to_string()).unwrap_or_default()
}

fn opt_fmt_i64(v: Option<i64>) -> String {
    v.map(|x| x.to_string()).unwrap_or_default()
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "true" | "on" | "yes" => Some(true),
        "0" | "false" | "off" | "no" => Some(false),
        _ => None,
    }
}

fn parse_usize_csv(value: &str) -> Result<Vec<usize>, String> {
    let mut out = Vec::new();
    for raw in value.split(',') {
        let piece = raw.trim();
        if piece.is_empty() {
            continue;
        }
        let n = piece
            .parse::<usize>()
            .map_err(|err| format!("'{piece}' is not a usize: {err}"))?;
        out.push(n);
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err("expected at least one integer".to_string());
    }
    Ok(out)
}

fn parse_critical_overflow_policy(value: &str) -> Option<CriticalOverflowPolicy> {
    match value {
        "drop-newest" => Some(CriticalOverflowPolicy::DropNewest),
        "drop-oldest" => Some(CriticalOverflowPolicy::DropOldest),
        "block" | "block-with-timeout" => Some(CriticalOverflowPolicy::BlockWithTimeout),
        _ => None,
    }
}

fn parse_args() -> Result<SimArgs, String> {
    let mut scenario = Scenario::Compare;
    let mut compare_order = CompareOrder::DirectFirst;
    let mut warmup_secs = 0u64;
    let mut autotune = false;
    let mut autotune_telemetry_caps = vec![24, 32, 48];
    let mut autotune_critical_caps = vec![64, 96, 128];
    let mut repeats = 1usize;
    let mut output = OutputFormat::Text;
    let mut output_path: Option<String> = None;
    let mut server_addr = SocketAddr::from_str("127.0.0.1:52100")
        .map_err(|err| format!("invalid default server addr: {err}"))?;
    let mut proxy_addr = SocketAddr::from_str("127.0.0.1:52101")
        .map_err(|err| format!("invalid default proxy addr: {err}"))?;
    let mut metrics_addr = SocketAddr::from_str("127.0.0.1:52102")
        .map_err(|err| format!("invalid default metrics addr: {err}"))?;
    let mut clients = DEFAULT_CLIENTS;
    let mut tick_hz = DEFAULT_TICK_HZ;
    let mut duration_secs = DEFAULT_DURATION_SECS;
    let mut telemetry_per_tick = DEFAULT_TELEMETRY_PER_TICK;
    let mut max_packets_per_tick = DEFAULT_MAX_PACKETS_PER_TICK;
    let mut jitter_ms = DEFAULT_JITTER_MS;
    let mut drop_rate = DEFAULT_DROP_RATE;
    let mut proxy_workers = DEFAULT_PROXY_WORKERS;
    let mut proxy_batch_size = DEFAULT_PROXY_BATCH_SIZE;
    let mut proxy_queue_capacity = DEFAULT_PROXY_QUEUE_CAPACITY;
    let mut proxy_telemetry_queue_capacity = DEFAULT_PROXY_TELEMETRY_QUEUE_CAPACITY;
    let mut proxy_critical_queue_capacity = DEFAULT_PROXY_CRITICAL_QUEUE_CAPACITY;
    let mut proxy_downstream_telemetry_queue_capacity: Option<usize> = None;
    let mut proxy_downstream_critical_queue_capacity: Option<usize> = None;
    let mut proxy_critical_overflow_policy = CriticalOverflowPolicy::DropOldest;
    let mut proxy_critical_block_timeout_millis = DEFAULT_PROXY_CRITICAL_BLOCK_TIMEOUT_MILLIS;
    let mut proxy_downstream_telemetry_ttl_millis = DEFAULT_PROXY_DOWNSTREAM_TELEMETRY_TTL_MILLIS;
    let mut proxy_downstream_critical_ttl_millis = DEFAULT_PROXY_DOWNSTREAM_CRITICAL_TTL_MILLIS;

    for raw in env::args().skip(1) {
        if raw == "--help" || raw == "-h" {
            print_help();
            std::process::exit(0);
        }

        let Some((k, v)) = raw.split_once('=') else {
            return Err(format!(
                "invalid arg '{raw}'. expected --key=value. use --help"
            ));
        };
        match k {
            "--scenario" => {
                scenario = match v {
                    "direct" => Scenario::Direct,
                    "proxied" => Scenario::Proxied,
                    "compare" => Scenario::Compare,
                    _ => {
                        return Err(format!(
                            "invalid --scenario '{v}', use direct|proxied|compare"
                        ))
                    }
                };
            }
            "--compare-order" => {
                compare_order = match v {
                    "direct-first" => CompareOrder::DirectFirst,
                    "proxied-first" => CompareOrder::ProxiedFirst,
                    "alternate" => CompareOrder::Alternate,
                    _ => {
                        return Err(format!(
                        "invalid --compare-order '{v}', use direct-first|proxied-first|alternate"
                    ))
                    }
                };
            }
            "--warmup-secs" => {
                warmup_secs = v
                    .parse::<u64>()
                    .map_err(|err| format!("invalid --warmup-secs '{v}': {err}"))?;
            }
            "--autotune" => {
                autotune = parse_bool(v).ok_or_else(|| {
                    format!("invalid --autotune '{v}', use true|false|on|off|1|0")
                })?;
            }
            "--autotune-telemetry-caps" => {
                autotune_telemetry_caps = parse_usize_csv(v)
                    .map_err(|err| format!("invalid --autotune-telemetry-caps '{v}': {err}"))?;
            }
            "--autotune-critical-caps" => {
                autotune_critical_caps = parse_usize_csv(v)
                    .map_err(|err| format!("invalid --autotune-critical-caps '{v}': {err}"))?;
            }
            "--repeats" => {
                repeats = v
                    .parse::<usize>()
                    .map_err(|err| format!("invalid --repeats '{v}': {err}"))?;
            }
            "--output" => {
                output = match v {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    "csv" => OutputFormat::Csv,
                    _ => return Err(format!("invalid --output '{v}', use text|json|csv")),
                };
            }
            "--output-path" => {
                output_path = Some(v.to_string());
            }
            "--server" => {
                server_addr = v
                    .parse::<SocketAddr>()
                    .map_err(|err| format!("invalid --server '{v}': {err}"))?;
            }
            "--proxy" => {
                proxy_addr = v
                    .parse::<SocketAddr>()
                    .map_err(|err| format!("invalid --proxy '{v}': {err}"))?;
            }
            "--metrics" => {
                metrics_addr = v
                    .parse::<SocketAddr>()
                    .map_err(|err| format!("invalid --metrics '{v}': {err}"))?;
            }
            "--clients" => {
                clients = v
                    .parse::<usize>()
                    .map_err(|err| format!("invalid --clients '{v}': {err}"))?;
            }
            "--tick-hz" => {
                tick_hz = v
                    .parse::<u64>()
                    .map_err(|err| format!("invalid --tick-hz '{v}': {err}"))?;
            }
            "--duration-secs" => {
                duration_secs = v
                    .parse::<u64>()
                    .map_err(|err| format!("invalid --duration-secs '{v}': {err}"))?;
            }
            "--telemetry-per-tick" => {
                telemetry_per_tick = v
                    .parse::<usize>()
                    .map_err(|err| format!("invalid --telemetry-per-tick '{v}': {err}"))?;
            }
            "--server-max-packets-per-tick" => {
                max_packets_per_tick = v
                    .parse::<usize>()
                    .map_err(|err| format!("invalid --server-max-packets-per-tick '{v}': {err}"))?;
            }
            "--jitter-ms" => {
                jitter_ms = v
                    .parse::<u64>()
                    .map_err(|err| format!("invalid --jitter-ms '{v}': {err}"))?;
            }
            "--drop-rate" => {
                drop_rate = v
                    .parse::<f64>()
                    .map_err(|err| format!("invalid --drop-rate '{v}': {err}"))?;
            }
            "--proxy-workers" | "--proxy-worker-count" => {
                proxy_workers = v
                    .parse::<usize>()
                    .map_err(|err| format!("invalid {k} '{v}': {err}"))?;
            }
            "--proxy-batch-size" => {
                proxy_batch_size = v
                    .parse::<usize>()
                    .map_err(|err| format!("invalid --proxy-batch-size '{v}': {err}"))?;
            }
            "--proxy-queue-capacity" => {
                proxy_queue_capacity = v
                    .parse::<usize>()
                    .map_err(|err| format!("invalid --proxy-queue-capacity '{v}': {err}"))?;
            }
            "--proxy-telemetry-queue-capacity" => {
                proxy_telemetry_queue_capacity = v.parse::<usize>().map_err(|err| {
                    format!("invalid --proxy-telemetry-queue-capacity '{v}': {err}")
                })?;
            }
            "--proxy-critical-queue-capacity" => {
                proxy_critical_queue_capacity = v.parse::<usize>().map_err(|err| {
                    format!("invalid --proxy-critical-queue-capacity '{v}': {err}")
                })?;
            }
            "--proxy-downstream-telemetry-queue-capacity" => {
                let cap = v.parse::<usize>().map_err(|err| {
                    format!("invalid --proxy-downstream-telemetry-queue-capacity '{v}': {err}")
                })?;
                if cap == 0 {
                    return Err(
                        "--proxy-downstream-telemetry-queue-capacity must be > 0".to_string()
                    );
                }
                proxy_downstream_telemetry_queue_capacity = Some(cap);
            }
            "--proxy-downstream-critical-queue-capacity" => {
                let cap = v.parse::<usize>().map_err(|err| {
                    format!("invalid --proxy-downstream-critical-queue-capacity '{v}': {err}")
                })?;
                if cap == 0 {
                    return Err(
                        "--proxy-downstream-critical-queue-capacity must be > 0".to_string()
                    );
                }
                proxy_downstream_critical_queue_capacity = Some(cap);
            }
            "--proxy-critical-overflow" => {
                proxy_critical_overflow_policy =
                    parse_critical_overflow_policy(v).ok_or_else(|| {
                        format!(
                            "invalid --proxy-critical-overflow '{v}', use drop-newest|drop-oldest|block-with-timeout"
                        )
                    })?;
            }
            "--proxy-critical-block-timeout-ms" => {
                proxy_critical_block_timeout_millis = v.parse::<u64>().map_err(|err| {
                    format!("invalid --proxy-critical-block-timeout-ms '{v}': {err}")
                })?;
            }
            "--proxy-downstream-telemetry-ttl-ms" => {
                proxy_downstream_telemetry_ttl_millis = v.parse::<u64>().map_err(|err| {
                    format!("invalid --proxy-downstream-telemetry-ttl-ms '{v}': {err}")
                })?;
            }
            "--proxy-downstream-critical-ttl-ms" => {
                proxy_downstream_critical_ttl_millis = v.parse::<u64>().map_err(|err| {
                    format!("invalid --proxy-downstream-critical-ttl-ms '{v}': {err}")
                })?;
            }
            _ => return Err(format!("unknown arg '{k}'. use --help")),
        }
    }

    if clients == 0 {
        return Err("--clients must be > 0".to_string());
    }
    if repeats == 0 {
        return Err("--repeats must be > 0".to_string());
    }
    if tick_hz == 0 {
        return Err("--tick-hz must be > 0".to_string());
    }
    if duration_secs == 0 {
        return Err("--duration-secs must be > 0".to_string());
    }
    if warmup_secs >= duration_secs {
        return Err("--warmup-secs must be smaller than --duration-secs".to_string());
    }
    if telemetry_per_tick == 0 {
        return Err("--telemetry-per-tick must be > 0".to_string());
    }
    if max_packets_per_tick == 0 {
        return Err("--server-max-packets-per-tick must be > 0".to_string());
    }
    if !(0.0..=1.0).contains(&drop_rate) {
        return Err("--drop-rate must be in [0, 1]".to_string());
    }
    if proxy_workers == 0 {
        return Err("--proxy-workers must be > 0".to_string());
    }
    if proxy_batch_size == 0 {
        return Err("--proxy-batch-size must be > 0".to_string());
    }
    if proxy_queue_capacity == 0
        || proxy_telemetry_queue_capacity == 0
        || proxy_critical_queue_capacity == 0
    {
        return Err("proxy queue capacities must be > 0".to_string());
    }
    if autotune
        && (autotune_telemetry_caps.is_empty()
            || autotune_critical_caps.is_empty()
            || autotune_telemetry_caps.contains(&0)
            || autotune_critical_caps.contains(&0))
    {
        return Err(
            "autotune caps must be non-empty and contain values > 0 (comma-separated)".to_string(),
        );
    }

    Ok(SimArgs {
        scenario,
        compare_order,
        warmup_secs,
        autotune,
        autotune_telemetry_caps,
        autotune_critical_caps,
        repeats,
        output,
        output_path,
        server_addr,
        proxy_addr,
        metrics_addr,
        clients,
        tick_hz,
        duration_secs,
        telemetry_per_tick,
        max_packets_per_tick,
        jitter_ms,
        drop_rate,
        proxy_workers,
        proxy_batch_size,
        proxy_queue_capacity,
        proxy_telemetry_queue_capacity,
        proxy_critical_queue_capacity,
        proxy_downstream_telemetry_queue_capacity,
        proxy_downstream_critical_queue_capacity,
        proxy_critical_overflow_policy,
        proxy_critical_block_timeout_millis,
        proxy_downstream_telemetry_ttl_millis,
        proxy_downstream_critical_ttl_millis,
    })
}

fn print_help() {
    println!(
        "nx_eos_sim - defensive matchmaking/lag resilience harness\n\
         usage:\n\
         \tcargo run -p nx_proxy --bin nx_eos_sim -- --scenario=compare\n\
         options:\n\
         \t--scenario=direct|proxied|compare (default compare)\n\
         \t--compare-order=direct-first|proxied-first|alternate (default direct-first)\n\
         \t--warmup-secs=0\n\
         \t--autotune=false (true enables queue grid search; requires scenario=compare)\n\
         \t--autotune-telemetry-caps=24,32,48\n\
         \t--autotune-critical-caps=64,96,128\n\
         \t--repeats=1\n\
         \t--output=text|json|csv (default text)\n\
         \t--output-path=./nx_eos_sim_report.json\n\
         \t--server=127.0.0.1:52100\n\
         \t--proxy=127.0.0.1:52101\n\
         \t--metrics=127.0.0.1:52102\n\
         \t--clients=8\n\
         \t--tick-hz=60\n\
         \t--duration-secs=10\n\
         \t--telemetry-per-tick=40\n\
         \t--server-max-packets-per-tick=80\n\
         \t--jitter-ms=30\n\
         \t--drop-rate=0.03\n\
         \t--proxy-workers=1\n\
         \t--proxy-batch-size=32\n\
         \t--proxy-queue-capacity=96\n\
         \t--proxy-telemetry-queue-capacity=48\n\
         \t--proxy-critical-queue-capacity=64\n\
         \t--proxy-downstream-telemetry-queue-capacity=48 (optional; defaults to proxy-telemetry-queue-capacity)\n\
         \t--proxy-downstream-critical-queue-capacity=64 (optional; defaults to proxy-critical-queue-capacity)\n\
         \t--proxy-critical-overflow=drop-newest|drop-oldest|block-with-timeout\n\
         \t--proxy-critical-block-timeout-ms=5\n\
         \t--proxy-downstream-telemetry-ttl-ms=0\n\
         \t--proxy-downstream-critical-ttl-ms=0\n"
    );
}
