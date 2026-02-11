use std::collections::{HashMap, HashSet, VecDeque};
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

const DEFAULT_CLIENTS: usize = 8;
const DEFAULT_TICK_HZ: u64 = 60;
const DEFAULT_DURATION_SECS: u64 = 10;
const DEFAULT_TELEMETRY_PER_TICK: usize = 40;
const DEFAULT_MAX_PACKETS_PER_TICK: usize = 80;
const DEFAULT_JITTER_MS: u64 = 30;
const DEFAULT_DROP_RATE: f64 = 0.03;

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
    clients: usize,
    tick_hz: u64,
    duration_secs: u64,
    telemetry_per_tick: usize,
    max_packets_per_tick: usize,
    jitter_ms: u64,
    drop_rate: f64,
}

#[derive(Debug, Default)]
struct ServerStats {
    assigned_matches: u64,
    packets_critical: u64,
    packets_telemetry: u64,
    packets_other: u64,
    snapshots_sent: u64,
}

#[derive(Debug, Default)]
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

#[derive(Debug, Default)]
struct TrialResult {
    metrics: TrialMetrics,
    server: ServerStats,
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

    match args.scenario {
        Scenario::Direct => {
            let result = run_trial(&args, false)?;
            print_result("direct", &result);
        }
        Scenario::Proxied => {
            let result = run_trial(&args, true)?;
            print_result("proxied", &result);
        }
        Scenario::Compare => {
            let direct = run_trial(&args, false)?;
            let proxied = run_trial(&args, true)?;
            print_result("direct", &direct);
            print_result("proxied", &proxied);
            println!(
                "delta control_lag_avg={:.3} p99={:.3} matched={} -> {} snapshots={} -> {}",
                direct.metrics.control_lag_avg - proxied.metrics.control_lag_avg,
                direct.metrics.control_lag_p99 - proxied.metrics.control_lag_p99,
                direct.metrics.matched_clients,
                proxied.metrics.matched_clients,
                direct.metrics.recv_snapshots,
                proxied.metrics.recv_snapshots
            );
        }
    }

    Ok(())
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
        let cfg = proxy_config(args.proxy_addr, args.server_addr, args.metrics_addr);
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
    let tick_sleep = Duration::from_micros(1_000_000 / args.tick_hz.max(1));
    let mut recv_buf = [0u8; 2048];

    for _ in 0..total_ticks {
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
            max_sessions: 4096,
            min_datagram_bytes: 1,
            max_datagram_bytes: 1400,
            drop_udp_fragments: true,
            queue_capacity: 96,
            telemetry_queue_capacity: Some(48),
            critical_queue_capacity: Some(64),
            critical_overflow_policy: CriticalOverflowPolicy::DropNewest,
            critical_block_timeout_millis: 5,
            telemetry_prefixes: vec!["TELE:".to_string()],
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

fn print_result(name: &str, result: &TrialResult) {
    println!(
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
    );
}

fn parse_args() -> Result<SimArgs, String> {
    let mut scenario = Scenario::Compare;
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
            _ => return Err(format!("unknown arg '{k}'. use --help")),
        }
    }

    if clients == 0 {
        return Err("--clients must be > 0".to_string());
    }
    if tick_hz == 0 {
        return Err("--tick-hz must be > 0".to_string());
    }
    if duration_secs == 0 {
        return Err("--duration-secs must be > 0".to_string());
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

    Ok(SimArgs {
        scenario,
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
    })
}

fn print_help() {
    println!(
        "nx_eos_sim - defensive matchmaking/lag resilience harness\n\
         usage:\n\
         \tcargo run -p nx_proxy --bin nx_eos_sim -- --scenario=compare\n\
         options:\n\
         \t--scenario=direct|proxied|compare (default compare)\n\
         \t--server=127.0.0.1:52100\n\
         \t--proxy=127.0.0.1:52101\n\
         \t--metrics=127.0.0.1:52102\n\
         \t--clients=8\n\
         \t--tick-hz=60\n\
         \t--duration-secs=10\n\
         \t--telemetry-per-tick=40\n\
         \t--server-max-packets-per-tick=80\n\
         \t--jitter-ms=30\n\
         \t--drop-rate=0.03\n"
    );
}
