use std::collections::{HashMap, VecDeque};
use std::env;
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

const TICK_HZ: u64 = 60;
const TICK_DT: f32 = 1.0 / (TICK_HZ as f32);
const DEFAULT_TICKS: u32 = 1_200;
const DEFAULT_TELEMETRY_PER_TICK: usize = 120;
const DEFAULT_MAX_PACKETS_PER_TICK: usize = 48;
const DEFAULT_LAG_DELAY_MS: u64 = 45;
const DEFAULT_LAG_DROP: f64 = 0.05;

#[derive(Clone, Copy, Debug)]
enum Scenario {
    Direct,
    Proxied,
    Compare,
}

#[derive(Clone, Debug)]
struct SimArgs {
    scenario: Scenario,
    server_addr: SocketAddr,
    proxy_addr: SocketAddr,
    metrics_addr: SocketAddr,
    ticks: u32,
    telemetry_per_tick: usize,
    max_packets_per_tick: usize,
    lag_delay_ms: u64,
    lag_drop_rate: f64,
}

#[derive(Clone, Copy, Debug, Default)]
struct CarState {
    pos: f32,
    vel: f32,
    throttle: f32,
}

#[derive(Clone, Copy, Debug, Default)]
struct BallState {
    pos: f32,
    vel: f32,
}

#[derive(Debug, Default)]
struct ServerStats {
    packets_critical: u64,
    packets_telemetry: u64,
    packets_other: u64,
    snapshots_sent: u64,
    last_match_id: u32,
}

#[derive(Debug, Default)]
struct ClientMetrics {
    sent_critical: u64,
    sent_telemetry: u64,
    recv_snapshots: u64,
    out_dropped: u64,
    in_dropped: u64,
    avg_error: f64,
    p99_error: f64,
}

#[derive(Debug, Default)]
struct TrialResult {
    metrics: ClientMetrics,
    server: ServerStats,
}

#[derive(Debug)]
struct OutPacket {
    send_at: Instant,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct InPacket {
    deliver_at: Instant,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct MatchState {
    next_match_id: u32,
    client_to_match: HashMap<SocketAddr, u32>,
}

impl MatchState {
    fn new() -> Self {
        Self {
            next_match_id: 1,
            client_to_match: HashMap::new(),
        }
    }

    fn assign_or_get(&mut self, client: SocketAddr) -> u32 {
        if let Some(existing) = self.client_to_match.get(&client).copied() {
            return existing;
        }
        let id = self.next_match_id;
        self.next_match_id = self.next_match_id.saturating_add(1);
        self.client_to_match.insert(client, id);
        id
    }
}

#[derive(Debug)]
struct LagInjector {
    delay_ms: u64,
    drop_rate: f64,
    rng: SimpleRng,
}

impl LagInjector {
    fn new(delay_ms: u64, drop_rate: f64, seed: u64) -> Self {
        Self {
            delay_ms,
            drop_rate: drop_rate.clamp(0.0, 1.0),
            rng: SimpleRng::new(seed),
        }
    }

    fn should_drop(&mut self) -> bool {
        self.rng.next_f64() < self.drop_rate
    }

    fn ready_in(&mut self) -> Duration {
        if self.delay_ms == 0 {
            return Duration::ZERO;
        }
        let jitter = self.rng.next_u64() % (self.delay_ms.saturating_add(1));
        Duration::from_millis(jitter)
    }
}

#[derive(Debug)]
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        let seed = if seed == 0 {
            0x1234_5678_9ABC_DEF0
        } else {
            seed
        };
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64*
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

fn main() -> Result<(), String> {
    let args = parse_args()?;

    match args.scenario {
        Scenario::Direct => {
            let result = run_trial(&args, false)?;
            print_trial("direct", &result);
        }
        Scenario::Proxied => {
            let result = run_trial(&args, true)?;
            print_trial("proxied", &result);
        }
        Scenario::Compare => {
            let direct = run_trial(&args, false)?;
            let proxied = run_trial(&args, true)?;
            print_trial("direct", &direct);
            print_trial("proxied", &proxied);
            println!(
                "delta avg_error={:.4} p99_error={:.4} recv_snapshots={} -> {}",
                direct.metrics.avg_error - proxied.metrics.avg_error,
                direct.metrics.p99_error - proxied.metrics.p99_error,
                direct.metrics.recv_snapshots,
                proxied.metrics.recv_snapshots
            );
        }
    }

    Ok(())
}

fn run_trial(args: &SimArgs, use_proxy: bool) -> Result<TrialResult, String> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_thread = spawn_server(
        args.server_addr,
        args.max_packets_per_tick,
        shutdown.clone(),
    )?;

    let mut proxy_runtime = None::<Runtime>;
    let mut proxy_shutdown = None::<CancellationToken>;
    if use_proxy {
        let rt = Runtime::new().map_err(|err| format!("failed to create tokio runtime: {err}"))?;
        let token = CancellationToken::new();
        let cfg = proxy_config(args.proxy_addr, args.server_addr, args.metrics_addr);
        let child = token.clone();
        rt.spawn(async move {
            if let Err(err) = run_proxy(cfg, child).await {
                eprintln!("nx_rl_sim proxy task ended with error: {err}");
            }
        });
        proxy_runtime = Some(rt);
        proxy_shutdown = Some(token);
        thread::sleep(Duration::from_millis(200));
    }

    let target_addr = if use_proxy {
        args.proxy_addr
    } else {
        args.server_addr
    };
    let metrics = run_client(args, target_addr)?;

    if let Some(token) = proxy_shutdown {
        token.cancel();
    }
    if let Some(rt) = proxy_runtime {
        rt.shutdown_timeout(Duration::from_millis(300));
    }

    shutdown.store(true, Ordering::Relaxed);
    let server_stats = server_thread
        .join()
        .map_err(|_| "server thread panicked".to_string())?;

    Ok(TrialResult {
        metrics,
        server: server_stats,
    })
}

fn spawn_server(
    bind_addr: SocketAddr,
    max_packets_per_tick: usize,
    shutdown: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<ServerStats>, String> {
    let socket = UdpSocket::bind(bind_addr)
        .map_err(|err| format!("failed to bind simulation server {bind_addr}: {err}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("failed to set server nonblocking: {err}"))?;

    let handle = thread::spawn(move || {
        let mut stats = ServerStats::default();
        let mut cars: HashMap<SocketAddr, CarState> = HashMap::new();
        let mut ball = BallState::default();
        let mut matcher = MatchState::new();
        let mut tick: u64 = 0;
        let tick_sleep = Duration::from_micros(1_000_000 / TICK_HZ);
        let mut recv_buf = [0u8; 2048];

        while !shutdown.load(Ordering::Relaxed) {
            let tick_started = Instant::now();
            let mut processed = 0usize;
            while processed < max_packets_per_tick {
                let recv = socket.recv_from(&mut recv_buf);
                let (len, peer) = match recv {
                    Ok(frame) => frame,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                };
                processed = processed.saturating_add(1);
                if len == 0 {
                    continue;
                }

                let msg = match std::str::from_utf8(&recv_buf[..len]) {
                    Ok(v) => v,
                    Err(_) => {
                        stats.packets_other = stats.packets_other.saturating_add(1);
                        continue;
                    }
                };

                if msg.starts_with("HELLO ") {
                    let match_id = matcher.assign_or_get(peer);
                    stats.last_match_id = match_id;
                    let _ = socket.send_to(format!("MATCH {match_id} READY").as_bytes(), peer);
                    cars.entry(peer).or_default();
                    continue;
                }

                if let Some((seq, throttle)) = parse_critical_input(msg) {
                    let car = cars.entry(peer).or_default();
                    car.throttle = throttle;
                    // A tiny seq touch to avoid complete no-op and simulate input freshness.
                    if seq % 120 == 0 {
                        car.vel *= 0.999;
                    }
                    stats.packets_critical = stats.packets_critical.saturating_add(1);
                    continue;
                }

                if msg.starts_with("TELE:") {
                    stats.packets_telemetry = stats.packets_telemetry.saturating_add(1);
                    continue;
                }

                stats.packets_other = stats.packets_other.saturating_add(1);
            }

            for car in cars.values_mut() {
                car.vel = (car.vel + car.throttle * 25.0 * TICK_DT) * 0.985;
                car.pos += car.vel * TICK_DT;
                if car.pos.abs() > 45.0 {
                    car.pos = car.pos.signum() * 45.0;
                    car.vel *= -0.45;
                }
            }

            let avg_car_pos = if cars.is_empty() {
                0.0
            } else {
                cars.values().map(|c| c.pos).sum::<f32>() / cars.len() as f32
            };
            ball.vel += (avg_car_pos - ball.pos) * 0.65 * TICK_DT;
            ball.vel *= 0.992;
            ball.pos += ball.vel * TICK_DT;
            if ball.pos.abs() > 60.0 {
                ball.pos = ball.pos.signum() * 60.0;
                ball.vel *= -0.55;
            }

            tick = tick.saturating_add(1);
            for (client, car) in &cars {
                let snap = format!(
                    "SNAP {tick} {:.4} {:.4} {:.4} {:.4}",
                    car.pos, car.vel, ball.pos, ball.vel
                );
                if socket.send_to(snap.as_bytes(), client).is_ok() {
                    stats.snapshots_sent = stats.snapshots_sent.saturating_add(1);
                }
            }

            let elapsed = tick_started.elapsed();
            if elapsed < tick_sleep {
                thread::sleep(tick_sleep - elapsed);
            }
        }

        stats
    });

    Ok(handle)
}

fn run_client(args: &SimArgs, target_addr: SocketAddr) -> Result<ClientMetrics, String> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind client socket: {err}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("failed to set client nonblocking: {err}"))?;

    let hello = b"HELLO local_tester";
    socket
        .send_to(hello, target_addr)
        .map_err(|err| format!("failed to send HELLO: {err}"))?;

    let mut out_lag = LagInjector::new(args.lag_delay_ms, args.lag_drop_rate, 0xCAFE_BABE_0011);
    let mut in_lag = LagInjector::new(args.lag_delay_ms, args.lag_drop_rate, 0xC0DE_1234_AAAA);
    let mut out_q = VecDeque::<OutPacket>::new();
    let mut in_q = VecDeque::<InPacket>::new();
    let mut recv_buf = [0u8; 2048];

    let tick_sleep = Duration::from_micros(1_000_000 / TICK_HZ);
    let mut local_car = CarState::default();
    let mut local_ball = BallState::default();
    let mut errors = Vec::<f64>::with_capacity(args.ticks as usize);
    let mut metrics = ClientMetrics::default();

    for tick in 0..args.ticks {
        let tick_started = Instant::now();
        let throttle = if (tick / 90) % 2 == 0 { 1.0 } else { -1.0 };

        local_car.vel = (local_car.vel + throttle * 25.0 * TICK_DT) * 0.985;
        local_car.pos += local_car.vel * TICK_DT;
        local_ball.vel += (local_car.pos - local_ball.pos) * 0.65 * TICK_DT;
        local_ball.vel *= 0.992;
        local_ball.pos += local_ball.vel * TICK_DT;

        queue_outbound(
            &mut out_lag,
            &mut out_q,
            format!("CRIT:IN {tick} {throttle:.3}").into_bytes(),
            &mut metrics.out_dropped,
        );
        metrics.sent_critical = metrics.sent_critical.saturating_add(1);

        for i in 0..args.telemetry_per_tick {
            queue_outbound(
                &mut out_lag,
                &mut out_q,
                format!("TELE:spam:{tick}:{i}").into_bytes(),
                &mut metrics.out_dropped,
            );
            metrics.sent_telemetry = metrics.sent_telemetry.saturating_add(1);
        }

        flush_outbound(&socket, target_addr, &mut out_q);
        recv_into_inbound(
            &socket,
            &mut in_lag,
            &mut in_q,
            &mut recv_buf,
            &mut metrics.in_dropped,
        );
        process_inbound(
            &mut in_q,
            &mut local_car,
            &mut local_ball,
            &mut errors,
            &mut metrics.recv_snapshots,
        );

        let elapsed = tick_started.elapsed();
        if elapsed < tick_sleep {
            thread::sleep(tick_sleep - elapsed);
        }
    }

    let flush_deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < flush_deadline {
        flush_outbound(&socket, target_addr, &mut out_q);
        recv_into_inbound(
            &socket,
            &mut in_lag,
            &mut in_q,
            &mut recv_buf,
            &mut metrics.in_dropped,
        );
        process_inbound(
            &mut in_q,
            &mut local_car,
            &mut local_ball,
            &mut errors,
            &mut metrics.recv_snapshots,
        );
        thread::sleep(Duration::from_millis(4));
    }

    if !errors.is_empty() {
        let mut sorted = errors.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((sorted.len() - 1) as f64 * 0.99).round() as usize;
        metrics.avg_error = errors.iter().sum::<f64>() / errors.len() as f64;
        metrics.p99_error = sorted[idx.min(sorted.len() - 1)];
    }

    Ok(metrics)
}

fn queue_outbound(
    lag: &mut LagInjector,
    queue: &mut VecDeque<OutPacket>,
    bytes: Vec<u8>,
    dropped: &mut u64,
) {
    if lag.should_drop() {
        *dropped = dropped.saturating_add(1);
        return;
    }
    queue.push_back(OutPacket {
        send_at: Instant::now() + lag.ready_in(),
        bytes,
    });
}

fn flush_outbound(socket: &UdpSocket, target: SocketAddr, queue: &mut VecDeque<OutPacket>) {
    let now = Instant::now();
    loop {
        let Some(pkt) = queue.front() else {
            break;
        };
        if pkt.send_at > now {
            break;
        }
        let pkt = queue.pop_front().expect("packet just checked");
        let _ = socket.send_to(&pkt.bytes, target);
    }
}

fn recv_into_inbound(
    socket: &UdpSocket,
    lag: &mut LagInjector,
    queue: &mut VecDeque<InPacket>,
    recv_buf: &mut [u8],
    dropped: &mut u64,
) {
    loop {
        match socket.recv_from(recv_buf) {
            Ok((len, _peer)) => {
                if lag.should_drop() {
                    *dropped = dropped.saturating_add(1);
                    continue;
                }
                queue.push_back(InPacket {
                    deliver_at: Instant::now() + lag.ready_in(),
                    bytes: recv_buf[..len].to_vec(),
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

fn process_inbound(
    queue: &mut VecDeque<InPacket>,
    local_car: &mut CarState,
    local_ball: &mut BallState,
    errors: &mut Vec<f64>,
    recv_snapshots: &mut u64,
) {
    let now = Instant::now();
    loop {
        let Some(pkt) = queue.front() else {
            break;
        };
        if pkt.deliver_at > now {
            break;
        }
        let pkt = queue.pop_front().expect("packet just checked");
        let msg = match std::str::from_utf8(&pkt.bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some((server_car_pos, server_ball_pos)) = parse_snapshot(msg) else {
            continue;
        };
        *recv_snapshots = recv_snapshots.saturating_add(1);
        errors.push((local_car.pos - server_car_pos).abs() as f64);
        // Soft reconciliation to mimic client-side prediction correction.
        local_car.pos = (local_car.pos * 0.82) + (server_car_pos * 0.18);
        local_ball.pos = (local_ball.pos * 0.86) + (server_ball_pos * 0.14);
    }
}

fn parse_critical_input(msg: &str) -> Option<(u32, f32)> {
    // CRIT:IN <seq> <throttle>
    let mut parts = msg.split_whitespace();
    let head = parts.next()?;
    if head != "CRIT:IN" {
        return None;
    }
    let seq = parts.next()?.parse::<u32>().ok()?;
    let throttle = parts.next()?.parse::<f32>().ok()?;
    Some((seq, throttle.clamp(-1.0, 1.0)))
}

fn parse_snapshot(msg: &str) -> Option<(f32, f32)> {
    // SNAP tick car_pos car_vel ball_pos ball_vel
    let mut parts = msg.split_whitespace();
    if parts.next()? != "SNAP" {
        return None;
    }
    let _tick = parts.next()?;
    let car_pos = parts.next()?.parse::<f32>().ok()?;
    let _car_vel = parts.next()?;
    let ball_pos = parts.next()?.parse::<f32>().ok()?;
    Some((car_pos, ball_pos))
}

fn proxy_config(
    listen_addr: SocketAddr,
    upstream_addr: SocketAddr,
    metrics_addr: SocketAddr,
) -> ProxyConfig {
    ProxyConfig {
        proxy: ProxySection {
            listen_addr,
            upstream_addr,
            worker_count: 1,
            reuse_port: true,
            pin_workers: false,
            batch_size: 32,
            max_sessions: 1024,
            min_datagram_bytes: 1,
            max_datagram_bytes: 1400,
            drop_udp_fragments: true,
            queue_capacity: 64,
            telemetry_queue_capacity: Some(32),
            critical_queue_capacity: Some(32),
            downstream_telemetry_queue_capacity: None,
            downstream_critical_queue_capacity: None,
            critical_overflow_policy: CriticalOverflowPolicy::DropOldest,
            critical_block_timeout_millis: 5,
            downstream_telemetry_ttl_millis: 0,
            downstream_critical_ttl_millis: 0,
            telemetry_prefixes: vec!["TELE:".to_string()],
            telemetry_prefixes_upstream: Vec::new(),
            telemetry_prefixes_downstream: Vec::new(),
        },
        rate_limit: RateLimitSection {
            per_ip_packets_per_second: 200_000.0,
            per_ip_burst_packets: 200_000.0,
            per_ip_bytes_per_second: 200_000_000.0,
            per_ip_burst_bytes: 200_000_000.0,
            global_packets_per_second: 200_000.0,
            global_burst_packets: 200_000.0,
            global_bytes_per_second: 200_000_000.0,
            global_burst_bytes: 200_000_000.0,
            subnet_enabled: false,
            subnet_ipv4_prefix: 24,
            subnet_ipv6_prefix: 64,
            subnet_packets_per_second: 50_000.0,
            subnet_burst_packets: 50_000.0,
            subnet_bytes_per_second: 50_000_000.0,
            subnet_burst_bytes: 50_000_000.0,
            max_ip_buckets: 4096,
            max_subnet_buckets: 1024,
            idle_timeout_secs: 60,
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

fn parse_args() -> Result<SimArgs, String> {
    let mut scenario = Scenario::Compare;
    let mut server_addr = SocketAddr::from_str("127.0.0.1:52000")
        .map_err(|err| format!("invalid default server addr: {err}"))?;
    let mut proxy_addr = SocketAddr::from_str("127.0.0.1:52001")
        .map_err(|err| format!("invalid default proxy addr: {err}"))?;
    let mut metrics_addr = SocketAddr::from_str("127.0.0.1:52002")
        .map_err(|err| format!("invalid default metrics addr: {err}"))?;
    let mut ticks = DEFAULT_TICKS;
    let mut telemetry = DEFAULT_TELEMETRY_PER_TICK;
    let mut max_packets = DEFAULT_MAX_PACKETS_PER_TICK;
    let mut lag_delay_ms = DEFAULT_LAG_DELAY_MS;
    let mut lag_drop = DEFAULT_LAG_DROP;

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
                            "invalid scenario '{v}', use direct|proxied|compare"
                        ))
                    }
                }
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
            "--ticks" => {
                ticks = v
                    .parse::<u32>()
                    .map_err(|err| format!("invalid --ticks '{v}': {err}"))?;
            }
            "--telemetry-per-tick" => {
                telemetry = v
                    .parse::<usize>()
                    .map_err(|err| format!("invalid --telemetry-per-tick '{v}': {err}"))?;
            }
            "--server-max-packets-per-tick" => {
                max_packets = v
                    .parse::<usize>()
                    .map_err(|err| format!("invalid --server-max-packets-per-tick '{v}': {err}"))?;
            }
            "--lag-delay-ms" => {
                lag_delay_ms = v
                    .parse::<u64>()
                    .map_err(|err| format!("invalid --lag-delay-ms '{v}': {err}"))?;
            }
            "--lag-drop" => {
                lag_drop = v
                    .parse::<f64>()
                    .map_err(|err| format!("invalid --lag-drop '{v}': {err}"))?;
            }
            _ => return Err(format!("unknown arg '{k}'. use --help")),
        }
    }

    if ticks == 0 {
        return Err("--ticks must be > 0".to_string());
    }
    if telemetry == 0 {
        return Err("--telemetry-per-tick must be > 0".to_string());
    }
    if max_packets == 0 {
        return Err("--server-max-packets-per-tick must be > 0".to_string());
    }
    if !(0.0..=1.0).contains(&lag_drop) {
        return Err("--lag-drop must be in [0, 1]".to_string());
    }

    Ok(SimArgs {
        scenario,
        server_addr,
        proxy_addr,
        metrics_addr,
        ticks,
        telemetry_per_tick: telemetry,
        max_packets_per_tick: max_packets,
        lag_delay_ms,
        lag_drop_rate: lag_drop,
    })
}

fn print_trial(name: &str, result: &TrialResult) {
    println!(
        "{name}: avg_error={:.4} p99_error={:.4} recv_snapshots={} sent_critical={} sent_telemetry={} out_drop={} in_drop={} server_crit={} server_tele={} server_snap={}",
        result.metrics.avg_error,
        result.metrics.p99_error,
        result.metrics.recv_snapshots,
        result.metrics.sent_critical,
        result.metrics.sent_telemetry,
        result.metrics.out_dropped,
        result.metrics.in_dropped,
        result.server.packets_critical,
        result.server.packets_telemetry,
        result.server.snapshots_sent
    );
}

fn print_help() {
    println!(
        "nx_rl_sim - mini UDP Rocket League-like lag simulation\n\
         usage:\n\
         \tcargo run -p nx_proxy --bin nx_rl_sim -- --scenario=compare\n\
         options:\n\
         \t--scenario=direct|proxied|compare (default compare)\n\
         \t--server=127.0.0.1:52000\n\
         \t--proxy=127.0.0.1:52001\n\
         \t--metrics=127.0.0.1:52002\n\
         \t--ticks=1200\n\
         \t--telemetry-per-tick=120\n\
         \t--server-max-packets-per-tick=48\n\
         \t--lag-delay-ms=45\n\
         \t--lag-drop=0.05\n"
    );
}
