use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use flume::{Receiver, Sender, TrySendError};
use nx_metrics::ProxyMetrics;
use nx_netio::{DatagramRef, MsgBuf};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

#[cfg(all(feature = "netio_mmsg", target_os = "linux"))]
use nx_netio::{RecvBatchState, SendBatchState};
#[cfg(all(feature = "netio_mmsg", target_os = "linux"))]
use std::os::fd::AsRawFd;

use crate::anomaly::AnomalyDetector;
use crate::challenge::{now_unix_secs, ChallengeGate, GateDecision};
use crate::config::{CriticalOverflowPolicy, ProxyConfig};
use crate::lane::{classify_lane, TrafficLane};
use crate::mmr::MmrDetector;
use crate::packet::{validate_packet, PacketLimits, PacketValidationPolicy, CHECKSUM_HEADER_LEN};
use crate::rate_limit::{MultiScopeRateLimiter, RateLimiterConfig};

#[derive(Debug)]
struct SessionHandle {
    critical_tx: Sender<Vec<u8>>,
    telemetry_tx: Sender<Vec<u8>>,
    critical_tap_rx: Receiver<Vec<u8>>,
    telemetry_tap_rx: Receiver<Vec<u8>>,
    last_seen: Instant,
    session_shutdown: CancellationToken,
}

#[derive(Debug)]
struct DownstreamPacket {
    client_addr: SocketAddr,
    payload: Vec<u8>,
    lane: TrafficLane,
    enqueued_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueOutcome {
    Enqueued,
    Dropped { reason: &'static str },
    DroppedOldestEnqueued { reason: &'static str },
    Disconnected,
}

struct IngressIo {
    bufs: Vec<MsgBuf>,
    #[cfg(all(feature = "netio_mmsg", target_os = "linux"))]
    recv_state: RecvBatchState,
}

impl IngressIo {
    fn new(batch_size: usize, max_datagram_bytes: usize) -> Self {
        let bufs = (0..batch_size.max(1))
            .map(|_| MsgBuf::with_capacity(max_datagram_bytes.max(1)))
            .collect::<Vec<_>>();
        Self {
            bufs,
            #[cfg(all(feature = "netio_mmsg", target_os = "linux"))]
            recv_state: RecvBatchState::new(batch_size.max(1)),
        }
    }

    async fn recv(&mut self, socket: &UdpSocket, metrics: &ProxyMetrics) -> io::Result<usize> {
        #[cfg(all(feature = "netio_mmsg", target_os = "linux"))]
        {
            loop {
                match socket.try_io(tokio::io::Interest::READABLE, || {
                    nx_netio::recv_batch_with_state(
                        socket.as_raw_fd(),
                        &mut self.bufs,
                        &mut self.recv_state,
                    )
                }) {
                    Ok(n) if n > 0 => {
                        metrics.record_udp_netio_recv_batch(n);
                        return Ok(n);
                    }
                    Ok(_) => return Ok(0),
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        socket.readable().await?;
                    }
                    Err(err) if err.kind() == io::ErrorKind::Unsupported => break,
                    Err(err) => return Err(err),
                }
            }
        }

        #[cfg(not(all(feature = "netio_mmsg", target_os = "linux")))]
        let _ = metrics;

        let n = nx_netio::recv_batch_tokio(socket, &mut self.bufs).await?;
        Ok(n)
    }
}

struct EgressIo {
    #[cfg(all(feature = "netio_mmsg", target_os = "linux"))]
    send_state: SendBatchState,
}

impl EgressIo {
    fn new(_batch_size: usize) -> Self {
        Self {
            #[cfg(all(feature = "netio_mmsg", target_os = "linux"))]
            send_state: SendBatchState::new(_batch_size.max(1)),
        }
    }

    async fn send(
        &mut self,
        socket: &UdpSocket,
        packets: &[DownstreamPacket],
        metrics: &ProxyMetrics,
    ) -> io::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        #[cfg(all(feature = "netio_mmsg", target_os = "linux"))]
        {
            let refs = packets
                .iter()
                .map(|pkt| DatagramRef {
                    payload: &pkt.payload,
                    addr: pkt.client_addr,
                })
                .collect::<Vec<_>>();

            match nx_netio::send_batch_with_state(socket.as_raw_fd(), &refs, &mut self.send_state) {
                Ok(sent) => {
                    metrics.record_udp_netio_send_batch(sent);
                    if sent < packets.len() {
                        let tail_refs = refs[sent..].to_vec();
                        let tail_sent = nx_netio::send_batch_tokio(socket, &tail_refs).await?;
                        return Ok(sent + tail_sent);
                    }
                    return Ok(sent);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) if err.kind() == io::ErrorKind::Unsupported => {}
                Err(err) => return Err(err),
            }
        }

        #[cfg(not(all(feature = "netio_mmsg", target_os = "linux")))]
        let _ = metrics;

        let refs = packets
            .iter()
            .map(|pkt| DatagramRef {
                payload: &pkt.payload,
                addr: pkt.client_addr,
            })
            .collect::<Vec<_>>();
        nx_netio::send_batch_tokio(socket, &refs).await
    }
}

pub async fn run_proxy(config: ProxyConfig, shutdown: CancellationToken) -> Result<()> {
    if config.proxy.worker_count > 1 && !config.proxy.reuse_port {
        bail!("proxy.reuse_port must be true when worker_count > 1");
    }
    #[cfg(not(unix))]
    if config.proxy.worker_count > 1 {
        bail!("worker sharding with reuse_port requires unix sockets on this build");
    }

    let metrics = ProxyMetrics::new("nx_proxy")?;
    let _exporter_thread = if config.metrics.enabled {
        Some(metrics.spawn_exporter(config.metrics.listen_addr)?)
    } else {
        None
    };

    let listen_addr = config.proxy.listen_addr;
    let mut workers = JoinSet::new();

    for worker_id in 0..config.proxy.worker_count {
        let socket = bind_worker_socket(config.proxy.listen_addr, config.proxy.reuse_port)
            .with_context(|| {
                format!(
                    "failed to bind worker {worker_id} socket on {}",
                    config.proxy.listen_addr
                )
            })?;

        let worker_cfg = config.clone();
        let worker_metrics = metrics.clone();
        let worker_shutdown = shutdown.child_token();
        workers.spawn(async move {
            if let Err(err) = run_worker(
                worker_id,
                socket,
                worker_cfg,
                worker_metrics,
                worker_shutdown,
            )
            .await
            {
                eprintln!("nx_proxy worker {worker_id} error: {err}");
            }
        });
    }

    println!(
        "nx_proxy listening on {}, upstream {}, workers {}, metrics {}",
        listen_addr,
        config.proxy.upstream_addr,
        config.proxy.worker_count,
        if config.metrics.enabled {
            config.metrics.listen_addr.to_string()
        } else {
            "disabled".to_string()
        }
    );

    shutdown.cancelled().await;
    shutdown.cancel();
    while workers.join_next().await.is_some() {}

    Ok(())
}

async fn run_worker(
    worker_id: usize,
    client_socket: UdpSocket,
    config: ProxyConfig,
    metrics: ProxyMetrics,
    shutdown: CancellationToken,
) -> Result<()> {
    if config.proxy.pin_workers {
        let _ = pin_current_thread(worker_id);
    }

    let client_socket = Arc::new(client_socket);
    let mut ingress_io = IngressIo::new(config.proxy.batch_size, config.proxy.max_datagram_bytes);
    let mut rate_limiter = MultiScopeRateLimiter::new(RateLimiterConfig::from(&config.rate_limit));
    let mut anomaly_detector = AnomalyDetector::new(&config.anomaly, &config.rate_limit);
    let mut mmr_detector = MmrDetector::new(&config.mmr);
    let mut challenge_gate = ChallengeGate::new(&config.cookie);
    let packet_limits = PacketLimits {
        min_packet_size: config.proxy.min_datagram_bytes,
        max_packet_size: config.proxy.max_datagram_bytes,
    };
    let packet_validation = PacketValidationPolicy {
        enabled: config.packet_validation.enabled,
        strict_mode: config.packet_validation.strict_mode,
        require_checksum: config.packet_validation.require_checksum,
        strip_checksum_header: config.packet_validation.strip_checksum_header,
    };
    let max_wire_packet_size = config.proxy.max_datagram_bytes
        + if packet_validation.enabled && packet_validation.require_checksum {
            CHECKSUM_HEADER_LEN
        } else {
            0
        };
    let telemetry_prefixes_upstream = Arc::new(config.proxy.telemetry_prefix_bytes_upstream());
    let telemetry_prefixes_downstream = Arc::new(config.proxy.telemetry_prefix_bytes_downstream());
    let critical_queue_capacity = config.proxy.critical_queue_capacity();
    let telemetry_queue_capacity = config.proxy.telemetry_queue_capacity();
    let downstream_critical_queue_capacity = config.proxy.downstream_critical_queue_capacity();
    let downstream_telemetry_queue_capacity = config.proxy.downstream_telemetry_queue_capacity();
    let critical_timeout = Duration::from_millis(config.proxy.critical_block_timeout_millis);

    let (downstream_critical_tx, downstream_critical_rx) =
        flume::bounded(downstream_critical_queue_capacity);
    let downstream_critical_tap = downstream_critical_rx.clone();
    let (downstream_telemetry_tx, downstream_telemetry_rx) =
        flume::bounded(downstream_telemetry_queue_capacity);
    let downstream_telemetry_tap = downstream_telemetry_rx.clone();

    let downstream_task = {
        let socket = Arc::clone(&client_socket);
        let metrics = metrics.clone();
        let shutdown = shutdown.child_token();
        let critical_ttl = Duration::from_millis(config.proxy.downstream_critical_ttl_millis);
        let telemetry_ttl = Duration::from_millis(config.proxy.downstream_telemetry_ttl_millis);
        tokio::spawn(async move {
            run_downstream_worker(
                socket,
                downstream_critical_rx,
                downstream_telemetry_rx,
                metrics,
                shutdown,
                config.proxy.batch_size,
                critical_ttl,
                telemetry_ttl,
            )
            .await
        })
    };

    let mut sessions: HashMap<SocketAddr, SessionHandle> = HashMap::new();
    let idle_timeout = Duration::from_secs(config.rate_limit.idle_timeout_secs.max(1));
    let mut cleanup_interval = tokio::time::interval(idle_timeout);
    cleanup_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut warned_fragment_limitation = false;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = cleanup_interval.tick() => {
                let now = Instant::now();
                sessions.retain(|_, session| {
                    let active = !session.critical_tx.is_disconnected() || !session.telemetry_tx.is_disconnected();
                    let keep = active && now.saturating_duration_since(session.last_seen) <= idle_timeout;
                    if !keep {
                        session.session_shutdown.cancel();
                    }
                    keep
                });
            }
            recv = ingress_io.recv(&client_socket, &metrics) => {
                let packet_count = match recv {
                    Ok(count) => count,
                    Err(_) => {
                        metrics.record_udp_drop("udp_recv_error");
                        metrics.record_drop("client_recv_error");
                        continue;
                    }
                };

                for msg in ingress_io.bufs.iter().take(packet_count) {
                    metrics.record_udp_packet_in();
                    let client_addr = msg.addr();
                    let raw_packet = msg.payload();

                    if raw_packet.is_empty() {
                        metrics.record_udp_drop("packet_empty");
                        metrics.record_drop("packet_empty");
                        continue;
                    }

                    if raw_packet.len() > max_wire_packet_size {
                        metrics.record_udp_drop("packet_too_large");
                        metrics.record_drop("packet_too_large");
                        continue;
                    }

                    if config.proxy.drop_udp_fragments && !warned_fragment_limitation {
                        // Best-effort note: UDP socket APIs used here do not expose
                        // reliable inbound IP fragmentation metadata.
                        warned_fragment_limitation = true;
                    }

                    let now_secs = now_unix_secs();
                    let payload = match challenge_gate.evaluate(client_addr, raw_packet, now_secs) {
                        GateDecision::Forward(payload) => payload,
                        GateDecision::ForwardVerified(payload) => {
                            metrics.record_challenge_verified();
                            payload
                        }
                        GateDecision::Challenge(challenge_packet) => {
                            metrics.record_challenge_issued();
                            if client_socket
                                .send_to(&challenge_packet, client_addr)
                                .await
                                .is_err()
                            {
                                metrics.record_udp_drop("cookie_challenge_send_error");
                                metrics.record_drop("challenge_send_error");
                            }
                            continue;
                        }
                        GateDecision::Drop(reason) => {
                            metrics.record_udp_drop(reason);
                            metrics.record_drop(reason);
                            continue;
                        }
                    };

                    let payload = match validate_packet(payload, packet_limits, packet_validation) {
                        Ok(payload) => payload,
                        Err(reason) => {
                            metrics.record_udp_drop(reason);
                            metrics.record_drop(reason);
                            continue;
                        }
                    };

                    if let Err(scope) = rate_limiter.allow(client_addr.ip(), payload.len()) {
                        metrics.record_udp_rate_limited(scope.as_label());
                        metrics.record_udp_drop("udp_rate_limited");
                        metrics.record_rate_limit_drop();
                        metrics.record_rate_limited();
                        metrics.record_drop("rate_limited");
                        continue;
                    }

                    let now = Instant::now();

                    if anomaly_detector
                        .check_anomaly_with_payload(client_addr.ip(), payload, now)
                        .is_some()
                    {
                        metrics.record_udp_drop("anomaly_suspected");
                        metrics.record_anomaly_drop();
                        metrics.record_drop("anomaly_suspected");
                        continue;
                    }

                    if mmr_detector
                        .check_smurf_with_payload(client_addr.ip(), payload, now)
                        .is_some()
                    {
                        metrics.record_udp_drop("mmr_smurf_suspected");
                        metrics.record_drop("mmr_smurf_suspected");
                        continue;
                    }

                    if !sessions.contains_key(&client_addr) {
                        if sessions.len() >= config.proxy.max_sessions {
                            metrics.record_udp_drop("session_limit_reached");
                            metrics.record_drop("session_limit_reached");
                            continue;
                        }

                        let session = match spawn_session(
                            client_addr,
                            config.proxy.upstream_addr,
                            critical_queue_capacity,
                            telemetry_queue_capacity,
                            config.proxy.critical_overflow_policy,
                            critical_timeout,
                            downstream_critical_tx.clone(),
                            downstream_critical_tap.clone(),
                            downstream_telemetry_tx.clone(),
                            downstream_telemetry_tap.clone(),
                            Arc::clone(&telemetry_prefixes_downstream),
                            metrics.clone(),
                            shutdown.child_token(),
                            config.proxy.max_datagram_bytes,
                        )
                            .await
                        {
                            Ok(session) => session,
                            Err(_) => {
                                metrics.record_udp_drop("session_spawn_error");
                                metrics.record_drop("session_spawn_error");
                                continue;
                            }
                        };
                        sessions.insert(client_addr, session);
                    }

                    let Some(session) = sessions.get_mut(&client_addr) else {
                        metrics.record_udp_drop("session_lookup_error");
                        metrics.record_drop("session_lookup_error");
                        continue;
                    };
                    session.last_seen = Instant::now();

                    let lane = classify_lane(payload, &telemetry_prefixes_upstream);
                    let queue_result = {
                        let payload = payload.to_vec();
                        enqueue_laned(
                            payload,
                            lane,
                            &session.critical_tx,
                            &session.critical_tap_rx,
                            &session.telemetry_tx,
                            &session.telemetry_tap_rx,
                            config.proxy.critical_overflow_policy,
                            critical_timeout,
                            false,
                            &metrics,
                            "client_to_upstream",
                        )
                        .await
                    };

                    handle_queue_outcome(&metrics, queue_result, "client_to_upstream");
                    if matches!(queue_result, QueueOutcome::Disconnected) {
                        if let Some(session) = sessions.remove(&client_addr) {
                            session.session_shutdown.cancel();
                        }
                    }
                }
            }
        }
    }

    shutdown.cancel();
    sessions.clear();
    let _ = downstream_task.await;
    Ok(())
}

fn handle_queue_outcome(metrics: &ProxyMetrics, outcome: QueueOutcome, direction: &'static str) {
    match outcome {
        QueueOutcome::Enqueued => {}
        QueueOutcome::Dropped { reason } => {
            metrics.record_udp_drop(reason);
            metrics.record_drop(reason);
            metrics.record_queue_full(direction);
        }
        QueueOutcome::DroppedOldestEnqueued { reason } => {
            metrics.record_udp_drop(reason);
            metrics.record_drop(reason);
            metrics.record_queue_full(direction);
        }
        QueueOutcome::Disconnected => {
            metrics.record_udp_drop("queue_disconnected");
            metrics.record_drop("queue_disconnected");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn spawn_session(
    client_addr: SocketAddr,
    upstream_addr: SocketAddr,
    critical_queue_capacity: usize,
    telemetry_queue_capacity: usize,
    critical_policy: CriticalOverflowPolicy,
    critical_timeout: Duration,
    downstream_critical_tx: Sender<DownstreamPacket>,
    downstream_critical_tap: Receiver<DownstreamPacket>,
    downstream_telemetry_tx: Sender<DownstreamPacket>,
    downstream_telemetry_tap: Receiver<DownstreamPacket>,
    telemetry_prefixes: Arc<Vec<Vec<u8>>>,
    metrics: ProxyMetrics,
    shutdown: CancellationToken,
    max_datagram_bytes: usize,
) -> Result<SessionHandle> {
    let bind_addr = match upstream_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };

    let bind_addr = bind_addr
        .to_socket_addrs()
        .context("invalid bind address")?
        .next()
        .context("no bind address resolved")?;

    let upstream_socket = UdpSocket::bind(bind_addr)
        .await
        .context("failed to bind upstream session socket")?;
    upstream_socket
        .connect(upstream_addr)
        .await
        .context("failed to connect upstream session socket")?;
    let upstream_socket = Arc::new(upstream_socket);

    let (critical_tx, critical_rx) = flume::bounded(critical_queue_capacity);
    let critical_tap_rx = critical_rx.clone();
    let (telemetry_tx, telemetry_rx) = flume::bounded(telemetry_queue_capacity);
    let telemetry_tap_rx = telemetry_rx.clone();

    let session_shutdown = shutdown.child_token();

    tokio::spawn(run_session_upstream_send_worker(
        Arc::clone(&upstream_socket),
        critical_rx,
        telemetry_rx,
        metrics.clone(),
        session_shutdown.clone(),
    ));

    tokio::spawn(run_session_upstream_recv_worker(
        client_addr,
        upstream_socket,
        downstream_critical_tx,
        downstream_critical_tap,
        downstream_telemetry_tx,
        downstream_telemetry_tap,
        telemetry_prefixes,
        critical_policy,
        critical_timeout,
        metrics,
        session_shutdown.clone(),
        max_datagram_bytes,
    ));

    Ok(SessionHandle {
        critical_tx,
        telemetry_tx,
        critical_tap_rx,
        telemetry_tap_rx,
        last_seen: Instant::now(),
        session_shutdown,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_session_upstream_send_worker(
    upstream_socket: Arc<UdpSocket>,
    critical_rx: Receiver<Vec<u8>>,
    telemetry_rx: Receiver<Vec<u8>>,
    metrics: ProxyMetrics,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;

            _ = shutdown.cancelled() => break,
            outbound = critical_rx.recv_async() => {
                let payload = match outbound {
                    Ok(payload) => payload,
                    Err(_) => {
                        if telemetry_rx.is_disconnected() {
                            break;
                        }
                        continue;
                    }
                };

                metrics.set_udp_queue_depth("client_to_upstream", "critical", critical_rx.len() as i64);
                metrics.set_udp_queue_depth("client_to_upstream", "telemetry", telemetry_rx.len() as i64);

                match upstream_socket.send(&payload).await {
                    Ok(_) => {
                        metrics.record_udp_packet_forwarded();
                        metrics.record_forwarded("client_to_upstream");
                    }
                    Err(_) => {
                        metrics.record_udp_drop("upstream_send_error");
                        metrics.record_drop("upstream_send_error");
                        break;
                    }
                }
            }
            outbound = telemetry_rx.recv_async() => {
                let payload = match outbound {
                    Ok(payload) => payload,
                    Err(_) => {
                        if critical_rx.is_disconnected() {
                            break;
                        }
                        continue;
                    }
                };

                metrics.set_udp_queue_depth("client_to_upstream", "critical", critical_rx.len() as i64);
                metrics.set_udp_queue_depth("client_to_upstream", "telemetry", telemetry_rx.len() as i64);

                match upstream_socket.send(&payload).await {
                    Ok(_) => {
                        metrics.record_udp_packet_forwarded();
                        metrics.record_forwarded("client_to_upstream");
                    }
                    Err(_) => {
                        metrics.record_udp_drop("upstream_send_error");
                        metrics.record_drop("upstream_send_error");
                        break;
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_session_upstream_recv_worker(
    client_addr: SocketAddr,
    upstream_socket: Arc<UdpSocket>,
    downstream_critical_tx: Sender<DownstreamPacket>,
    downstream_critical_tap: Receiver<DownstreamPacket>,
    downstream_telemetry_tx: Sender<DownstreamPacket>,
    downstream_telemetry_tap: Receiver<DownstreamPacket>,
    telemetry_prefixes: Arc<Vec<Vec<u8>>>,
    critical_policy: CriticalOverflowPolicy,
    critical_timeout: Duration,
    metrics: ProxyMetrics,
    shutdown: CancellationToken,
    max_datagram_bytes: usize,
) {
    let mut recv_buf = vec![0u8; max_datagram_bytes.max(1)];

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            recv = upstream_socket.recv(&mut recv_buf) => {
                let len = match recv {
                    Ok(len) => len,
                    Err(_) => {
                        metrics.record_udp_drop("upstream_recv_error");
                        metrics.record_drop("upstream_recv_error");
                        break;
                    }
                };

                if len == 0 {
                    metrics.record_udp_drop("upstream_packet_empty");
                    metrics.record_drop("upstream_packet_empty");
                    continue;
                }

                let payload = recv_buf[..len].to_vec();
                let lane = classify_lane(&payload, &telemetry_prefixes);
                let packet = DownstreamPacket {
                    client_addr,
                    payload,
                    lane,
                    enqueued_at: Instant::now(),
                };

                let queue_result = enqueue_laned(
                    packet,
                    lane,
                    &downstream_critical_tx,
                    &downstream_critical_tap,
                    &downstream_telemetry_tx,
                    &downstream_telemetry_tap,
                    critical_policy,
                    critical_timeout,
                    false,
                    &metrics,
                    "upstream_to_client",
                ).await;

                handle_queue_outcome(&metrics, queue_result, "upstream_to_client");
                if matches!(queue_result, QueueOutcome::Disconnected) {
                    break;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_downstream_worker(
    client_socket: Arc<UdpSocket>,
    critical_rx: Receiver<DownstreamPacket>,
    telemetry_rx: Receiver<DownstreamPacket>,
    metrics: ProxyMetrics,
    shutdown: CancellationToken,
    batch_size: usize,
    critical_ttl: Duration,
    telemetry_ttl: Duration,
) {
    let mut egress_io = EgressIo::new(batch_size.max(1));

    loop {
        let Some(first) = recv_prioritized(&critical_rx, &telemetry_rx, &shutdown).await else {
            break;
        };

        let mut batch = Vec::with_capacity(batch_size.max(1));
        batch.push(first);
        while batch.len() < batch.capacity() {
            if let Ok(packet) = critical_rx.try_recv() {
                batch.push(packet);
                continue;
            }
            if let Ok(packet) = telemetry_rx.try_recv() {
                batch.push(packet);
                continue;
            }
            break;
        }

        metrics.set_udp_queue_depth("upstream_to_client", "critical", critical_rx.len() as i64);
        metrics.set_udp_queue_depth("upstream_to_client", "telemetry", telemetry_rx.len() as i64);

        if !critical_ttl.is_zero() || !telemetry_ttl.is_zero() {
            let now = Instant::now();
            batch.retain(|pkt| {
                let ttl = match pkt.lane {
                    TrafficLane::Critical => critical_ttl,
                    TrafficLane::Telemetry => telemetry_ttl,
                };
                if ttl.is_zero() {
                    return true;
                }
                if now.saturating_duration_since(pkt.enqueued_at) <= ttl {
                    return true;
                }

                let reason = match pkt.lane {
                    TrafficLane::Critical => "downstream_stale_critical",
                    TrafficLane::Telemetry => "downstream_stale_telemetry",
                };
                metrics.record_udp_drop(reason);
                metrics.record_drop(reason);
                false
            });
        }

        if batch.is_empty() {
            continue;
        }

        match egress_io.send(&client_socket, &batch, &metrics).await {
            Ok(sent) => {
                for _ in 0..sent {
                    metrics.record_udp_packet_forwarded();
                    metrics.record_forwarded("upstream_to_client");
                }
            }
            Err(_) => {
                metrics.record_udp_drop("client_send_error");
                metrics.record_drop("client_send_error");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn enqueue_laned<T>(
    item: T,
    lane: TrafficLane,
    critical_tx: &Sender<T>,
    critical_tap_rx: &Receiver<T>,
    telemetry_tx: &Sender<T>,
    telemetry_tap_rx: &Receiver<T>,
    critical_policy: CriticalOverflowPolicy,
    critical_timeout: Duration,
    allow_blocking: bool,
    metrics: &ProxyMetrics,
    direction: &'static str,
) -> QueueOutcome {
    let outcome = match lane {
        TrafficLane::Telemetry => match telemetry_tx.try_send(item) {
            Ok(_) => QueueOutcome::Enqueued,
            Err(TrySendError::Disconnected(_)) => QueueOutcome::Disconnected,
            Err(TrySendError::Full(item)) => {
                let _ = telemetry_tap_rx.try_recv();
                match telemetry_tx.try_send(item) {
                    Ok(_) => QueueOutcome::DroppedOldestEnqueued {
                        reason: "queue_full_telemetry_drop_oldest",
                    },
                    Err(TrySendError::Full(_)) => QueueOutcome::Dropped {
                        reason: "queue_full_telemetry_drop",
                    },
                    Err(TrySendError::Disconnected(_)) => QueueOutcome::Disconnected,
                }
            }
        },
        TrafficLane::Critical => match critical_policy {
            CriticalOverflowPolicy::DropNewest => match critical_tx.try_send(item) {
                Ok(_) => QueueOutcome::Enqueued,
                Err(TrySendError::Disconnected(_)) => QueueOutcome::Disconnected,
                Err(TrySendError::Full(_)) => QueueOutcome::Dropped {
                    reason: "queue_full_critical_drop_newest",
                },
            },
            CriticalOverflowPolicy::DropOldest => match critical_tx.try_send(item) {
                Ok(_) => QueueOutcome::Enqueued,
                Err(TrySendError::Disconnected(_)) => QueueOutcome::Disconnected,
                Err(TrySendError::Full(item)) => {
                    let _ = critical_tap_rx.try_recv();
                    match critical_tx.try_send(item) {
                        Ok(_) => QueueOutcome::DroppedOldestEnqueued {
                            reason: "queue_full_critical_drop_oldest",
                        },
                        Err(TrySendError::Full(_)) => QueueOutcome::Dropped {
                            reason: "queue_full_critical_drop",
                        },
                        Err(TrySendError::Disconnected(_)) => QueueOutcome::Disconnected,
                    }
                }
            },
            CriticalOverflowPolicy::BlockWithTimeout => {
                // Never block the hot ingress path (worker thread) on per-session backpressure.
                // Blocking here causes cross-session head-of-line blocking and tail-latency spikes.
                if !allow_blocking {
                    // If we can't block, prioritize freshness: drop one oldest and try again.
                    match critical_tx.try_send(item) {
                        Ok(_) => QueueOutcome::Enqueued,
                        Err(TrySendError::Disconnected(_)) => QueueOutcome::Disconnected,
                        Err(TrySendError::Full(item)) => {
                            let _ = critical_tap_rx.try_recv();
                            match critical_tx.try_send(item) {
                                Ok(_) => QueueOutcome::DroppedOldestEnqueued {
                                    reason: "queue_full_critical_drop_oldest",
                                },
                                Err(TrySendError::Full(_)) => QueueOutcome::Dropped {
                                    reason: "queue_full_critical_drop",
                                },
                                Err(TrySendError::Disconnected(_)) => QueueOutcome::Disconnected,
                            }
                        }
                    }
                } else {
                    match tokio::time::timeout(critical_timeout, critical_tx.send_async(item)).await
                    {
                        Ok(Ok(_)) => QueueOutcome::Enqueued,
                        Ok(Err(_)) => QueueOutcome::Disconnected,
                        Err(_) => QueueOutcome::Dropped {
                            reason: "queue_full_critical_timeout",
                        },
                    }
                }
            }
        },
    };

    metrics.set_udp_queue_depth(direction, "critical", critical_tap_rx.len() as i64);
    metrics.set_udp_queue_depth(direction, "telemetry", telemetry_tap_rx.len() as i64);
    outcome
}

async fn recv_prioritized<T: Send + 'static>(
    critical_rx: &Receiver<T>,
    telemetry_rx: &Receiver<T>,
    shutdown: &CancellationToken,
) -> Option<T> {
    loop {
        if let Ok(item) = critical_rx.try_recv() {
            return Some(item);
        }

        if critical_rx.is_disconnected() && telemetry_rx.is_disconnected() {
            return None;
        }

        tokio::select! {
            biased;

            _ = shutdown.cancelled() => return None,
            recv = critical_rx.recv_async() => {
                match recv {
                    Ok(item) => return Some(item),
                    Err(_) => {
                        if telemetry_rx.is_disconnected() {
                            return None;
                        }
                    }
                }
            }
            recv = telemetry_rx.recv_async() => {
                match recv {
                    Ok(item) => return Some(item),
                    Err(_) => {
                        if critical_rx.is_disconnected() {
                            return None;
                        }
                    }
                }
            }
        }
    }
}

fn bind_worker_socket(listen_addr: SocketAddr, reuse_port: bool) -> Result<UdpSocket> {
    let domain = if listen_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .context("failed creating UDP socket")?;
    socket
        .set_reuse_address(true)
        .context("failed setting SO_REUSEADDR")?;

    #[cfg(unix)]
    if reuse_port {
        socket
            .set_reuse_port(true)
            .context("failed setting SO_REUSEPORT")?;
    }

    #[cfg(not(unix))]
    if reuse_port {
        let _ = reuse_port;
    }

    socket
        .bind(&listen_addr.into())
        .with_context(|| format!("failed binding UDP socket to {listen_addr}"))?;
    socket
        .set_nonblocking(true)
        .context("failed setting nonblocking mode")?;

    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).context("failed converting socket into tokio UdpSocket")
}

#[cfg(target_os = "linux")]
fn pin_current_thread(worker_id: usize) -> io::Result<()> {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1);
    let cpu = worker_id % cpu_count;
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
    }
    let rc = unsafe {
        libc::sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &set as *const libc::cpu_set_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn pin_current_thread(_worker_id: usize) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "cpu pinning is only available on linux",
    ))
}
