#[cfg(feature = "cuda_anomaly")]
use std::hint::black_box;
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use nx_netio::{MsgBuf, RecvBatchState};
use nx_proxy::anomaly::AnomalyDetector;
use nx_proxy::config::{AnomalyModel, AnomalySection, RateLimitSection};

const PACKETS: usize = 20_000;
#[cfg(target_os = "linux")]
const BATCH: usize = 32;
const ANOMALY_SAMPLES: usize = 20_000;
const ANOMALY_THRESHOLDS: [f32; 3] = [0.5, 0.7, 0.9];
const AUC_SWEEP_THRESHOLDS: [f64; 11] = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];

fn main() {
    let fallback_pps = bench_fallback_pps();
    println!("fallback_recv_from_pps={fallback_pps:.0}");

    #[cfg(target_os = "linux")]
    {
        let mmsg_pps = bench_mmsg_pps();
        println!("mmsg_recvmmsg_pps={mmsg_pps:.0}");
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("mmsg_recvmmsg_pps=unsupported");
    }

    let (p50_us, p99_us) = bench_queue_latency_us();
    println!("enqueue_forward_latency_p50_us={p50_us:.2}");
    println!("enqueue_forward_latency_p99_us={p99_us:.2}");

    let (anomaly_p50_us, anomaly_p99_us, anomaly_drop_ratio) = bench_anomaly_latency_us();
    println!("anomaly_latency_p50_us={anomaly_p50_us:.2}");
    println!("anomaly_latency_p99_us={anomaly_p99_us:.2}");
    println!("anomaly_drop_ratio={anomaly_drop_ratio:.4}");
    let mut cpu_threshold_metrics = Vec::with_capacity(ANOMALY_THRESHOLDS.len());
    for threshold in ANOMALY_THRESHOLDS {
        let (p50_us, p99_us, drop_ratio) = bench_anomaly_latency_for_threshold(threshold);
        let threshold_label = threshold_label(threshold);
        let (auc_estimate, drop_vs_auc) = bench_anomaly_auc_tradeoff_for_threshold(threshold);
        println!("anomaly_latency_p50_thresh_{threshold_label}={p50_us:.2}");
        println!("anomaly_latency_p99_thresh_{threshold_label}={p99_us:.2}");
        println!("anomaly_drop_ratio_thresh_{threshold_label}={drop_ratio:.4}");
        println!("anomaly_auc_thresh_{threshold_label}={auc_estimate:.4}");
        println!("anomaly_drop_ratio_vs_auc_thresh_{threshold_label}={drop_vs_auc:.4}");
        println!("anomaly_auc_vs_drop_tradeoff_thresh_{threshold_label}={drop_vs_auc:.4}");
        cpu_threshold_metrics.push((threshold, p50_us, p99_us, drop_ratio));
    }
    print_threshold_deltas("anomaly", &cpu_threshold_metrics);

    #[cfg(feature = "cuda_anomaly")]
    {
        let (cuda_p50_us, cuda_p99_us, cuda_drop_ratio) = bench_anomaly_latency_cuda_us();
        println!("anomaly_latency_cuda_p50_us={cuda_p50_us:.2}");
        println!("anomaly_latency_cuda_p99_us={cuda_p99_us:.2}");
        println!("anomaly_cuda_drop_ratio={cuda_drop_ratio:.4}");
        println!("anomaly_drop_ratio_cuda={cuda_drop_ratio:.4}");
        println!(
            "anomaly_latency_cpu_minus_cuda_p50_us={:.2}",
            anomaly_p50_us - cuda_p50_us
        );
        println!(
            "anomaly_latency_cpu_minus_cuda_p99_us={:.2}",
            anomaly_p99_us - cuda_p99_us
        );
        let mut cuda_threshold_metrics = Vec::with_capacity(ANOMALY_THRESHOLDS.len());
        for threshold in ANOMALY_THRESHOLDS {
            let (p50_us, p99_us, drop_ratio) = bench_anomaly_latency_for_threshold_cuda(threshold);
            let threshold_label = threshold_label(threshold);
            let (auc_estimate, drop_vs_auc) =
                bench_anomaly_auc_tradeoff_for_threshold_cuda(threshold);
            println!("anomaly_latency_cuda_p50_thresh_{threshold_label}={p50_us:.2}");
            println!("anomaly_latency_cuda_p99_thresh_{threshold_label}={p99_us:.2}");
            println!("anomaly_drop_ratio_cuda_thresh_{threshold_label}={drop_ratio:.4}");
            println!("anomaly_auc_cuda_thresh_{threshold_label}={auc_estimate:.4}");
            println!("anomaly_drop_ratio_vs_auc_cuda_thresh_{threshold_label}={drop_vs_auc:.4}");
            println!("anomaly_auc_vs_drop_tradeoff_cuda_thresh_{threshold_label}={drop_vs_auc:.4}");
            cuda_threshold_metrics.push((threshold, p50_us, p99_us, drop_ratio));
        }
        print_threshold_deltas("anomaly_cuda", &cuda_threshold_metrics);
    }
}

fn threshold_label(threshold: f32) -> String {
    format!("{threshold:.1}").replace('.', "_")
}

fn print_threshold_deltas(prefix: &str, metrics: &[(f32, f64, f64, f64)]) {
    for window in metrics.windows(2) {
        let (prev_t, prev_p50, prev_p99, prev_drop) = window[0];
        let (curr_t, curr_p50, curr_p99, curr_drop) = window[1];
        let curr_label = threshold_label(curr_t);
        let prev_label = threshold_label(prev_t);
        println!(
            "{prefix}_latency_p50_delta_thresh_{curr_label}_vs_{prev_label}={:.2}",
            curr_p50 - prev_p50
        );
        println!(
            "{prefix}_latency_p99_delta_thresh_{curr_label}_vs_{prev_label}={:.2}",
            curr_p99 - prev_p99
        );
        println!(
            "{prefix}_drop_ratio_delta_thresh_{curr_label}_vs_{prev_label}={:.4}",
            curr_drop - prev_drop
        );
    }
}

fn bench_fallback_pps() -> f64 {
    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
    let recv_addr = recv_socket.local_addr().expect("recv addr");
    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("bind send");
    send_socket.connect(recv_addr).expect("connect send");

    let payload = [0u8; 64];
    let mut recv_buf = [0u8; 1500];

    let start = Instant::now();
    for _ in 0..PACKETS {
        send_socket.send(&payload).expect("send");
        let _ = recv_socket.recv_from(&mut recv_buf).expect("recv");
    }
    let elapsed = start.elapsed().as_secs_f64();
    PACKETS as f64 / elapsed.max(1e-9)
}

#[cfg(target_os = "linux")]
fn bench_mmsg_pps() -> f64 {
    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
    let recv_addr = recv_socket.local_addr().expect("recv addr");
    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("bind send");
    send_socket.connect(recv_addr).expect("connect send");

    let payload = [0u8; 64];
    let mut msg_bufs = (0..BATCH)
        .map(|_| MsgBuf::with_capacity(1500))
        .collect::<Vec<_>>();
    let mut recv_state = RecvBatchState::new(BATCH);
    let recv_fd = recv_socket.as_raw_fd();

    let start = Instant::now();
    let mut received = 0usize;
    while received < PACKETS {
        let to_send = (PACKETS - received).min(BATCH);
        for _ in 0..to_send {
            send_socket.send(&payload).expect("send");
        }

        let mut got = 0usize;
        while got < to_send {
            let n = nx_netio::recv_batch_with_state(recv_fd, &mut msg_bufs, &mut recv_state)
                .expect("recvmmsg");
            got += n;
        }
        received += got;
    }

    let elapsed = start.elapsed().as_secs_f64();
    PACKETS as f64 / elapsed.max(1e-9)
}

fn bench_queue_latency_us() -> (f64, f64) {
    let (tx, rx) = flume::bounded::<Instant>(1024);
    let (ack_tx, ack_rx) = flume::bounded::<Instant>(1024);

    let worker = std::thread::spawn(move || {
        while let Ok(sent_at) = rx.recv() {
            let _ = ack_tx.send(sent_at);
        }
    });

    let mut latencies_us = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        let sent_at = Instant::now();
        tx.send(sent_at).expect("queue send");
        let echoed = ack_rx.recv().expect("queue recv");
        latencies_us.push(echoed.elapsed().as_secs_f64() * 1_000_000.0);
    }

    drop(tx);
    let _ = worker.join();

    latencies_us.sort_by(|a, b| a.partial_cmp(b).expect("valid float compare"));
    let p50 = percentile(&latencies_us, 0.50);
    let p99 = percentile(&latencies_us, 0.99);
    (p50, p99)
}

fn percentile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let idx = ((samples.len() - 1) as f64 * p).round() as usize;
    samples[idx.min(samples.len() - 1)]
}

fn bench_anomaly_latency_us() -> (f64, f64, f64) {
    let mut detector = AnomalyDetector::new(&anomaly_cfg(), &rate_cfg());
    let src = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1));
    let base = Instant::now();
    let mut latencies_us = Vec::with_capacity(ANOMALY_SAMPLES);
    let mut drops = 0usize;

    for i in 0..ANOMALY_SAMPLES {
        let now = base + Duration::from_millis((i / 20) as u64);
        let packet_len = if i % 13 == 0 { 1200 } else { 256 };
        let start = Instant::now();
        if detector.check_anomaly(src, packet_len, now).is_some() {
            drops = drops.saturating_add(1);
        }
        latencies_us.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }

    latencies_us.sort_by(|a, b| a.partial_cmp(b).expect("valid float compare"));
    let p50 = percentile(&latencies_us, 0.50);
    let p99 = percentile(&latencies_us, 0.99);
    let drop_ratio = drops as f64 / ANOMALY_SAMPLES as f64;
    (p50, p99, drop_ratio)
}

fn bench_anomaly_latency_for_threshold(threshold: f32) -> (f64, f64, f64) {
    let mut detector = AnomalyDetector::new(&anomaly_cfg_with_threshold(threshold), &rate_cfg());
    let src = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 11));
    let base = Instant::now();
    let mut latencies_us = Vec::with_capacity(ANOMALY_SAMPLES);
    let mut drops = 0usize;

    for i in 0..ANOMALY_SAMPLES {
        let now = base + Duration::from_millis((i / 20) as u64);
        let packet_len = if i % 13 == 0 { 1200 } else { 256 };
        let start = Instant::now();
        if detector.check_anomaly(src, packet_len, now).is_some() {
            drops = drops.saturating_add(1);
        }
        latencies_us.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }

    latencies_us.sort_by(|a, b| a.partial_cmp(b).expect("valid float compare"));
    let p50 = percentile(&latencies_us, 0.50);
    let p99 = percentile(&latencies_us, 0.99);
    let drop_ratio = drops as f64 / ANOMALY_SAMPLES as f64;
    (p50, p99, drop_ratio)
}

fn bench_anomaly_auc_tradeoff_for_threshold(threshold: f32) -> (f64, f64) {
    let mut detector = AnomalyDetector::new(&anomaly_cfg_with_threshold(threshold), &rate_cfg());
    let src = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 21));
    let base = Instant::now();
    let mut scored = Vec::with_capacity(ANOMALY_SAMPLES);
    let mut drops = 0usize;
    let mut evaluated = 0usize;

    for i in 0..ANOMALY_SAMPLES {
        let now = base + Duration::from_millis((i / 20) as u64);
        let is_anomaly = synthetic_anomaly_label(i);
        let packet_len = synthetic_packet_len(i, is_anomaly);
        if let Some(score) = detector.check_anomaly_score(src, packet_len, now) {
            let score = score as f64;
            scored.push((score, is_anomaly));
            evaluated = evaluated.saturating_add(1);
            if score >= threshold as f64 {
                drops = drops.saturating_add(1);
            }
        }
    }

    if evaluated == 0 {
        return (0.0, 0.0);
    }
    let drop_ratio = drops as f64 / evaluated as f64;
    let auc_estimate = auc_from_scored_samples(&scored);
    let drop_vs_auc = drop_ratio / auc_estimate.max(1e-9);
    (auc_estimate, drop_vs_auc)
}

fn anomaly_cfg() -> AnomalySection {
    anomaly_cfg_with_threshold(0.80)
}

fn anomaly_cfg_with_threshold(anomaly_threshold: f32) -> AnomalySection {
    AnomalySection {
        enabled: true,
        model: AnomalyModel::Heuristic,
        anomaly_threshold,
        ddos_limit: 500.0,
        window_millis: 200,
        ema_alpha: 0.35,
        min_packets_per_window: 8,
        max_tracked_ips: 1024,
        idle_timeout_secs: 60,
        torch_model_path: None,
    }
}

#[cfg(feature = "cuda_anomaly")]
fn anomaly_cfg_cuda() -> AnomalySection {
    let mut cfg = anomaly_cfg();
    #[cfg(feature = "cuda_anomaly_torch")]
    {
        cfg.model = AnomalyModel::Torch;
        cfg.torch_model_path = std::env::var("NX_ANOMALY_MODEL_PATH").ok();
    }
    #[cfg(not(feature = "cuda_anomaly_torch"))]
    {
        cfg.model = AnomalyModel::Heuristic;
        cfg.torch_model_path = None;
    }
    cfg
}

#[cfg(feature = "cuda_anomaly")]
fn anomaly_cfg_cuda_with_threshold(anomaly_threshold: f32) -> AnomalySection {
    let mut cfg = anomaly_cfg_with_threshold(anomaly_threshold);
    #[cfg(feature = "cuda_anomaly_torch")]
    {
        cfg.model = AnomalyModel::Torch;
        cfg.torch_model_path = std::env::var("NX_ANOMALY_MODEL_PATH").ok();
    }
    #[cfg(not(feature = "cuda_anomaly_torch"))]
    {
        cfg.model = AnomalyModel::Heuristic;
        cfg.torch_model_path = None;
    }
    cfg
}

#[cfg(feature = "cuda_anomaly")]
fn bench_anomaly_latency_cuda_us() -> (f64, f64, f64) {
    let mut detector = AnomalyDetector::new(&anomaly_cfg_cuda(), &rate_cfg());
    let src = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2));
    let base = Instant::now();
    let mut latencies_us = Vec::with_capacity(ANOMALY_SAMPLES);
    let mut drops = 0usize;

    for i in 0..ANOMALY_SAMPLES {
        let now = base + Duration::from_millis((i / 20) as u64);
        let packet_len = if i % 17 == 0 { 1300 } else { 256 };
        let start = Instant::now();
        let result = detector.check_anomaly(src, packet_len, now);
        if black_box(result).is_some() {
            drops = drops.saturating_add(1);
        }
        latencies_us.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }

    latencies_us.sort_by(|a, b| a.partial_cmp(b).expect("valid float compare"));
    let p50 = percentile(&latencies_us, 0.50);
    let p99 = percentile(&latencies_us, 0.99);
    let drop_ratio = drops as f64 / ANOMALY_SAMPLES as f64;
    (p50, p99, drop_ratio)
}

#[cfg(feature = "cuda_anomaly")]
fn bench_anomaly_latency_for_threshold_cuda(threshold: f32) -> (f64, f64, f64) {
    let mut detector =
        AnomalyDetector::new(&anomaly_cfg_cuda_with_threshold(threshold), &rate_cfg());
    let src = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 12));
    let base = Instant::now();
    let mut latencies_us = Vec::with_capacity(ANOMALY_SAMPLES);
    let mut drops = 0usize;

    for i in 0..ANOMALY_SAMPLES {
        let now = base + Duration::from_millis((i / 20) as u64);
        let packet_len = if i % 17 == 0 { 1300 } else { 256 };
        let start = Instant::now();
        let result = detector.check_anomaly(src, packet_len, now);
        if black_box(result).is_some() {
            drops = drops.saturating_add(1);
        }
        latencies_us.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }

    latencies_us.sort_by(|a, b| a.partial_cmp(b).expect("valid float compare"));
    let p50 = percentile(&latencies_us, 0.50);
    let p99 = percentile(&latencies_us, 0.99);
    let drop_ratio = drops as f64 / ANOMALY_SAMPLES as f64;
    (p50, p99, drop_ratio)
}

#[cfg(feature = "cuda_anomaly")]
fn bench_anomaly_auc_tradeoff_for_threshold_cuda(threshold: f32) -> (f64, f64) {
    let mut detector =
        AnomalyDetector::new(&anomaly_cfg_cuda_with_threshold(threshold), &rate_cfg());
    let src = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 22));
    let base = Instant::now();
    let mut scored = Vec::with_capacity(ANOMALY_SAMPLES);
    let mut drops = 0usize;
    let mut evaluated = 0usize;

    for i in 0..ANOMALY_SAMPLES {
        let now = base + Duration::from_millis((i / 20) as u64);
        let is_anomaly = synthetic_anomaly_label(i);
        let packet_len = synthetic_packet_len(i, is_anomaly);
        if let Some(score) = detector.check_anomaly_score(src, packet_len, now) {
            let score = score as f64;
            scored.push((score, is_anomaly));
            evaluated = evaluated.saturating_add(1);
            if score >= threshold as f64 {
                drops = drops.saturating_add(1);
            }
        }
    }

    if evaluated == 0 {
        return (0.0, 0.0);
    }
    let drop_ratio = drops as f64 / evaluated as f64;
    let auc_estimate = auc_from_scored_samples(&scored);
    let drop_vs_auc = drop_ratio / auc_estimate.max(1e-9);
    (auc_estimate, drop_vs_auc)
}

fn synthetic_anomaly_label(sample_idx: usize) -> bool {
    let periodic_spike = sample_idx.is_multiple_of(17);
    let burst_window = (sample_idx % 64) >= 48;
    periodic_spike || burst_window
}

fn synthetic_packet_len(sample_idx: usize, is_anomaly: bool) -> usize {
    if is_anomaly {
        if sample_idx.is_multiple_of(3) {
            1300
        } else {
            1100
        }
    } else if sample_idx.is_multiple_of(5) {
        320
    } else {
        256
    }
}

fn auc_from_scored_samples(samples: &[(f64, bool)]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let positives = samples.iter().filter(|(_, label)| *label).count() as f64;
    let negatives = samples.len() as f64 - positives;
    if positives <= 0.0 || negatives <= 0.0 {
        return 0.0;
    }

    let mut points = Vec::with_capacity(AUC_SWEEP_THRESHOLDS.len() + 2);
    points.push((0.0_f64, 0.0_f64));
    for &threshold in &AUC_SWEEP_THRESHOLDS {
        let mut tp = 0.0_f64;
        let mut fp = 0.0_f64;
        for &(score, label) in samples {
            if score >= threshold {
                if label {
                    tp += 1.0;
                } else {
                    fp += 1.0;
                }
            }
        }
        points.push((fp / negatives, tp / positives));
    }
    points.push((1.0_f64, 1.0_f64));
    points.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    let mut auc = 0.0_f64;
    for segment in points.windows(2) {
        let (x0, y0) = segment[0];
        let (x1, y1) = segment[1];
        let width = (x1 - x0).max(0.0);
        auc += width * (y0 + y1) * 0.5;
    }
    auc.clamp(0.0, 1.0)
}

fn rate_cfg() -> RateLimitSection {
    RateLimitSection {
        per_ip_packets_per_second: 500.0,
        per_ip_burst_packets: 1_000.0,
        per_ip_bytes_per_second: 500_000.0,
        per_ip_burst_bytes: 1_000_000.0,
        global_packets_per_second: 50_000.0,
        global_burst_packets: 100_000.0,
        global_bytes_per_second: 128_000_000.0,
        global_burst_bytes: 256_000_000.0,
        subnet_enabled: false,
        subnet_ipv4_prefix: 24,
        subnet_ipv6_prefix: 64,
        subnet_packets_per_second: 8_000.0,
        subnet_burst_packets: 16_000.0,
        subnet_bytes_per_second: 64_000_000.0,
        subnet_burst_bytes: 128_000_000.0,
        max_ip_buckets: 1024,
        max_subnet_buckets: 256,
        idle_timeout_secs: 120,
    }
}
