use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use nx_proxy::anomaly::AnomalyDetector;
use nx_proxy::challenge::build_response_packet_from_challenge;
use nx_proxy::config::{
    AnomalySection, CookieMode, CookieSection, CriticalOverflowPolicy, FloodSimSection,
    MetricsSection, MmrSection, PacketValidationSection, ProxyConfig, ProxySection,
    RateLimitSection,
};
use nx_proxy::packet::{cookie_header_len, COOKIE_MAGIC};
use nx_proxy::run_proxy;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[test]
fn anomaly_spike_drop() {
    let anomaly_cfg = AnomalySection {
        enabled: true,
        anomaly_threshold: 0.8,
        ddos_limit: 25.0,
        window_millis: 100,
        min_packets_per_window: 5,
        ..AnomalySection::default()
    };

    let rate_cfg = RateLimitSection {
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
        max_ip_buckets: 128,
        max_subnet_buckets: 64,
        idle_timeout_secs: 60,
    };

    let mut detector = AnomalyDetector::new(&anomaly_cfg, &rate_cfg);
    let peer = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let base = Instant::now();
    let mut dropped = false;
    for i in 0..1_000 {
        let now = base + Duration::from_millis((i / 10) as u64);
        if detector.check_anomaly(peer, 1_024, now).is_some() {
            dropped = true;
            break;
        }
    }
    assert!(dropped, "spike traffic should trigger anomaly drop");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn telemetry_spam_does_not_starve_critical() {
    let upstream_shutdown = CancellationToken::new();
    let (upstream_addr, upstream_task) = spawn_slow_echo_server(upstream_shutdown.clone()).await;

    let proxy_addr = pick_free_udp_addr();
    let metrics_addr = pick_free_tcp_addr();
    let config = base_config(proxy_addr, upstream_addr, metrics_addr);

    let proxy_shutdown = CancellationToken::new();
    let proxy_task = {
        let shutdown = proxy_shutdown.clone();
        tokio::spawn(async move { run_proxy(config, shutdown).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind test client socket");

    for _ in 0..300 {
        client
            .send_to(b"TEL:spam", proxy_addr)
            .await
            .expect("send telemetry");
    }

    let mut buf = [0u8; 2048];
    let mut saw_critical = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline && !saw_critical {
        client
            .send_to(b"CRIT:important", proxy_addr)
            .await
            .expect("send critical");

        let poll_deadline = tokio::time::Instant::now() + Duration::from_millis(350);
        while tokio::time::Instant::now() < poll_deadline {
            let recv = timeout(Duration::from_millis(60), client.recv_from(&mut buf)).await;
            let Ok(Ok((len, _))) = recv else {
                continue;
            };
            if &buf[..len] == b"CRIT:important" {
                saw_critical = true;
                break;
            }
        }
    }
    assert!(
        saw_critical,
        "critical payload was starved under telemetry spam"
    );

    let metrics = fetch_metrics(metrics_addr);
    assert!(
        metric_counter_with_labels(
            &metrics,
            "nx_proxy_udp_dropped_total",
            "reason=\"queue_full_telemetry\""
        ) > 0,
        "expected telemetry queue drops in metrics:\n{metrics}"
    );

    proxy_shutdown.cancel();
    let proxy_result = proxy_task.await.expect("proxy task join");
    assert!(
        proxy_result.is_ok(),
        "proxy returned error: {proxy_result:?}"
    );

    upstream_shutdown.cancel();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limiting_triggers_and_metrics_increment() {
    let upstream_shutdown = CancellationToken::new();
    let (upstream_addr, upstream_task) = spawn_echo_server(upstream_shutdown.clone()).await;

    let proxy_addr = pick_free_udp_addr();
    let metrics_addr = pick_free_tcp_addr();
    let mut config = base_config(proxy_addr, upstream_addr, metrics_addr);
    config.rate_limit.global_packets_per_second = 1.0;
    config.rate_limit.global_burst_packets = 1.0;
    config.rate_limit.per_ip_packets_per_second = 1.0;
    config.rate_limit.per_ip_burst_packets = 1.0;

    let proxy_shutdown = CancellationToken::new();
    let proxy_task = {
        let shutdown = proxy_shutdown.clone();
        tokio::spawn(async move { run_proxy(config, shutdown).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind test client socket");
    let mut buf = [0u8; 2048];

    client
        .send_to(b"CRIT:one", proxy_addr)
        .await
        .expect("send first");
    let _ = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
        .await
        .expect("first response timeout")
        .expect("first response receive");

    client
        .send_to(b"CRIT:two", proxy_addr)
        .await
        .expect("send second");
    let second = timeout(Duration::from_millis(350), client.recv_from(&mut buf)).await;
    assert!(second.is_err(), "second packet should be rate-limited");

    let metrics = fetch_metrics(metrics_addr);
    assert!(
        metric_counter_with_labels(
            &metrics,
            "nx_proxy_udp_rate_limited_total",
            "scope=\"global\""
        ) > 0
            || metric_counter_with_labels(
                &metrics,
                "nx_proxy_udp_rate_limited_total",
                "scope=\"ip\""
            ) > 0,
        "expected rate-limit metrics:\n{metrics}"
    );

    proxy_shutdown.cancel();
    let proxy_result = proxy_task.await.expect("proxy task join");
    assert!(
        proxy_result.is_ok(),
        "proxy returned error: {proxy_result:?}"
    );

    upstream_shutdown.cancel();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cookie_gate_rejects_until_valid_cookie_then_forwards() {
    let upstream_shutdown = CancellationToken::new();
    let (upstream_addr, upstream_task) = spawn_echo_server(upstream_shutdown.clone()).await;

    let proxy_addr = pick_free_udp_addr();
    let metrics_addr = pick_free_tcp_addr();
    let mut config = base_config(proxy_addr, upstream_addr, metrics_addr);
    config.cookie.enabled = true;
    config.cookie.mode = CookieMode::Strict;
    config.cookie.tag_bytes = 16;

    let proxy_shutdown = CancellationToken::new();
    let proxy_task = {
        let shutdown = proxy_shutdown.clone();
        tokio::spawn(async move { run_proxy(config, shutdown).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind test client socket");
    let mut buf = [0u8; 2048];

    client
        .send_to(b"CRIT:hello", proxy_addr)
        .await
        .expect("send raw");

    let (challenge_len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
        .await
        .expect("challenge timeout")
        .expect("challenge recv");

    let header_len = cookie_header_len(16);
    assert_eq!(challenge_len, header_len, "unexpected challenge size");
    assert_eq!(&buf[..4], &COOKIE_MAGIC);

    let response = build_response_packet_from_challenge(&buf[..challenge_len], b"CRIT:hello", 16)
        .expect("build response");
    client
        .send_to(&response, proxy_addr)
        .await
        .expect("send challenge response");

    let forward = timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await;
    let (len, _) = match forward {
        Ok(Ok(frame)) => frame,
        Ok(Err(err)) => panic!("forward recv failed: {err}"),
        Err(err) => {
            let metrics = fetch_metrics(metrics_addr);
            panic!("forward timeout: {err:?}\nmetrics:\n{metrics}");
        }
    };
    assert_eq!(&buf[..len], b"CRIT:hello");

    let metrics = fetch_metrics(metrics_addr);
    assert!(
        metric_counter(&metrics, "nx_proxy_challenge_issued_total") > 0,
        "expected cookie challenge issuance metric:\n{metrics}"
    );
    assert!(
        metric_counter(&metrics, "nx_proxy_challenge_verified_total") > 0,
        "expected cookie verification metric:\n{metrics}"
    );

    proxy_shutdown.cancel();
    let proxy_result = proxy_task.await.expect("proxy task join");
    assert!(
        proxy_result.is_ok(),
        "proxy returned error: {proxy_result:?}"
    );

    upstream_shutdown.cancel();
    let _ = upstream_task.await;
}

fn base_config(
    proxy_addr: SocketAddr,
    upstream_addr: SocketAddr,
    metrics_addr: SocketAddr,
) -> ProxyConfig {
    ProxyConfig {
        proxy: ProxySection {
            listen_addr: proxy_addr,
            upstream_addr,
            worker_count: 1,
            reuse_port: true,
            pin_workers: false,
            batch_size: 32,
            max_sessions: 1024,
            min_datagram_bytes: 1,
            max_datagram_bytes: 1400,
            drop_udp_fragments: true,
            queue_capacity: 16,
            telemetry_queue_capacity: Some(8),
            critical_queue_capacity: Some(8),
            critical_overflow_policy: CriticalOverflowPolicy::DropNewest,
            critical_block_timeout_millis: 10,
            telemetry_prefixes: vec!["TEL:".to_string()],
        },
        rate_limit: RateLimitSection {
            per_ip_packets_per_second: 100_000.0,
            per_ip_burst_packets: 100_000.0,
            per_ip_bytes_per_second: 100_000_000.0,
            per_ip_burst_bytes: 100_000_000.0,
            global_packets_per_second: 100_000.0,
            global_burst_packets: 100_000.0,
            global_bytes_per_second: 100_000_000.0,
            global_burst_bytes: 100_000_000.0,
            subnet_enabled: false,
            subnet_ipv4_prefix: 24,
            subnet_ipv6_prefix: 64,
            subnet_packets_per_second: 10_000.0,
            subnet_burst_packets: 20_000.0,
            subnet_bytes_per_second: 10_000_000.0,
            subnet_burst_bytes: 20_000_000.0,
            max_ip_buckets: 1024,
            max_subnet_buckets: 512,
            idle_timeout_secs: 30,
        },
        cookie: CookieSection {
            enabled: false,
            mode: CookieMode::Strict,
            secret: "integration-test-secret".to_string(),
            token_ttl_secs: 20,
            tag_bytes: 16,
            max_tracked_peers: 1024,
            challenge_packets_per_second: 1000.0,
            challenge_burst_packets: 1000.0,
        },
        anomaly: AnomalySection::default(),
        packet_validation: PacketValidationSection::default(),
        mmr: MmrSection::default(),
        flood_sim: FloodSimSection::default(),
        metrics: MetricsSection {
            enabled: true,
            listen_addr: metrics_addr,
        },
    }
}

fn metric_counter(snapshot: &str, metric_name: &str) -> u64 {
    snapshot
        .lines()
        .find_map(|line| {
            let prefix = format!("{metric_name} ");
            line.strip_prefix(&prefix)
                .and_then(|raw| raw.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

fn metric_counter_with_labels(snapshot: &str, metric_name: &str, labels: &str) -> u64 {
    let prefix = format!("{metric_name}{{{labels}}} ");
    snapshot
        .lines()
        .find_map(|line| {
            line.strip_prefix(&prefix)
                .and_then(|raw| raw.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

fn fetch_metrics(metrics_addr: SocketAddr) -> String {
    let mut stream =
        std::net::TcpStream::connect(metrics_addr).expect("connect to metrics endpoint");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set metrics read timeout");

    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write metrics request");

    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .expect("read metrics response");
    if let Some((_, body)) = resp.split_once("\r\n\r\n") {
        body.to_string()
    } else {
        resp
    }
}

fn pick_free_udp_addr() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("reserve UDP port");
    socket
        .local_addr()
        .expect("local addr for reserved UDP port")
}

fn pick_free_tcp_addr() -> SocketAddr {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve TCP port");
    socket
        .local_addr()
        .expect("local addr for reserved TCP port")
}

async fn spawn_echo_server(shutdown: CancellationToken) -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind upstream echo server");
    let addr = socket.local_addr().expect("upstream local addr");

    let task = tokio::spawn(async move {
        let mut buf = [0u8; 65_535];
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                recv = socket.recv_from(&mut buf) => {
                    let Ok((len, peer)) = recv else { break; };
                    if socket.send_to(&buf[..len], peer).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    (addr, task)
}

async fn spawn_slow_echo_server(shutdown: CancellationToken) -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind upstream slow echo server");
    let addr = socket.local_addr().expect("upstream local addr");

    let task = tokio::spawn(async move {
        let mut buf = [0u8; 65_535];
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                recv = socket.recv_from(&mut buf) => {
                    let Ok((len, peer)) = recv else { break; };
                    tokio::time::sleep(Duration::from_millis(8)).await;
                    if socket.send_to(&buf[..len], peer).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    (addr, task)
}
