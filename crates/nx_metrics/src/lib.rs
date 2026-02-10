use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;

use prometheus::{Encoder, IntCounter, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder};
use thiserror::Error;
use tiny_http::{Method, Response, Server, StatusCode};

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("prometheus registration failed: {0}")]
    Registration(#[from] prometheus::Error),
    #[error("unable to bind metrics endpoint: {0}")]
    Bind(String),
}

#[derive(Clone)]
pub struct ProxyMetrics {
    inner: Arc<Inner>,
}

struct Inner {
    registry: Registry,
    forwarded_total: IntCounterVec,
    dropped_total: IntCounterVec,
    rate_limited_total: IntCounter,
    queue_full_total: IntCounterVec,
    challenge_issued_total: IntCounter,
    challenge_verified_total: IntCounter,
    fbs_frames_forwarded_total: IntCounter,
    fbs_frames_dropped_total: IntCounterVec,
    fbs_queue_full_total: IntCounter,
    udp_pkts_in_total: IntCounter,
    udp_pkts_forwarded_total: IntCounter,
    udp_dropped_total: IntCounterVec,
    udp_rate_limited_total: IntCounterVec,
    udp_queue_depth: IntGaugeVec,
    udp_netio_recvmmsg_calls_total: IntCounter,
    udp_netio_recvmmsg_packets_total: IntCounter,
    udp_netio_sendmmsg_calls_total: IntCounter,
    udp_netio_sendmmsg_packets_total: IntCounter,
}

impl ProxyMetrics {
    pub fn new(namespace: &str) -> Result<Self, MetricsError> {
        let registry = Registry::new();

        let forwarded_total = IntCounterVec::new(
            Opts::new("forwarded_total", "Total forwarded packets").namespace(namespace),
            &["direction"],
        )?;
        let dropped_total = IntCounterVec::new(
            Opts::new("dropped_total", "Total dropped packets").namespace(namespace),
            &["reason"],
        )?;
        let rate_limited_total = IntCounter::with_opts(
            Opts::new(
                "rate_limited_total",
                "Total packets dropped due to rate limit",
            )
            .namespace(namespace),
        )?;
        let queue_full_total = IntCounterVec::new(
            Opts::new("queue_full_total", "Total queue overflow events").namespace(namespace),
            &["direction"],
        )?;
        let challenge_issued_total = IntCounter::with_opts(
            Opts::new(
                "challenge_issued_total",
                "Total stateless challenges issued",
            )
            .namespace(namespace),
        )?;
        let challenge_verified_total = IntCounter::with_opts(
            Opts::new(
                "challenge_verified_total",
                "Total challenge responses successfully verified",
            )
            .namespace(namespace),
        )?;
        let fbs_frames_forwarded_total = IntCounter::with_opts(
            Opts::new(
                "fbs_frames_forwarded_total",
                "Total FlatBuffers frames forwarded",
            )
            .namespace(namespace),
        )?;
        let fbs_frames_dropped_total = IntCounterVec::new(
            Opts::new(
                "fbs_frames_dropped_total",
                "Total FlatBuffers frames dropped",
            )
            .namespace(namespace),
            &["reason"],
        )?;
        let fbs_queue_full_total = IntCounter::with_opts(
            Opts::new(
                "fbs_queue_full_total",
                "Total FlatBuffers queue-full events",
            )
            .namespace(namespace),
        )?;

        let udp_pkts_in_total = IntCounter::with_opts(
            Opts::new("udp_pkts_in_total", "Total UDP packets received").namespace(namespace),
        )?;
        let udp_pkts_forwarded_total = IntCounter::with_opts(
            Opts::new("udp_pkts_forwarded_total", "Total UDP packets forwarded")
                .namespace(namespace),
        )?;
        let udp_dropped_total = IntCounterVec::new(
            Opts::new("udp_dropped_total", "Total UDP packets dropped").namespace(namespace),
            &["reason"],
        )?;
        let udp_rate_limited_total = IntCounterVec::new(
            Opts::new("udp_rate_limited_total", "Total UDP packets rate-limited")
                .namespace(namespace),
            &["scope"],
        )?;
        let udp_queue_depth = IntGaugeVec::new(
            Opts::new(
                "udp_queue_depth",
                "Current UDP queue depth per direction and lane",
            )
            .namespace(namespace),
            &["direction", "lane"],
        )?;
        let udp_netio_recvmmsg_calls_total = IntCounter::with_opts(
            Opts::new(
                "udp_netio_recvmmsg_calls_total",
                "Total recvmmsg syscall calls",
            )
            .namespace(namespace),
        )?;
        let udp_netio_recvmmsg_packets_total = IntCounter::with_opts(
            Opts::new(
                "udp_netio_recvmmsg_packets_total",
                "Total packets returned by recvmmsg",
            )
            .namespace(namespace),
        )?;
        let udp_netio_sendmmsg_calls_total = IntCounter::with_opts(
            Opts::new(
                "udp_netio_sendmmsg_calls_total",
                "Total sendmmsg syscall calls",
            )
            .namespace(namespace),
        )?;
        let udp_netio_sendmmsg_packets_total = IntCounter::with_opts(
            Opts::new(
                "udp_netio_sendmmsg_packets_total",
                "Total packets submitted through sendmmsg",
            )
            .namespace(namespace),
        )?;

        registry.register(Box::new(forwarded_total.clone()))?;
        registry.register(Box::new(dropped_total.clone()))?;
        registry.register(Box::new(rate_limited_total.clone()))?;
        registry.register(Box::new(queue_full_total.clone()))?;
        registry.register(Box::new(challenge_issued_total.clone()))?;
        registry.register(Box::new(challenge_verified_total.clone()))?;
        registry.register(Box::new(fbs_frames_forwarded_total.clone()))?;
        registry.register(Box::new(fbs_frames_dropped_total.clone()))?;
        registry.register(Box::new(fbs_queue_full_total.clone()))?;
        registry.register(Box::new(udp_pkts_in_total.clone()))?;
        registry.register(Box::new(udp_pkts_forwarded_total.clone()))?;
        registry.register(Box::new(udp_dropped_total.clone()))?;
        registry.register(Box::new(udp_rate_limited_total.clone()))?;
        registry.register(Box::new(udp_queue_depth.clone()))?;
        registry.register(Box::new(udp_netio_recvmmsg_calls_total.clone()))?;
        registry.register(Box::new(udp_netio_recvmmsg_packets_total.clone()))?;
        registry.register(Box::new(udp_netio_sendmmsg_calls_total.clone()))?;
        registry.register(Box::new(udp_netio_sendmmsg_packets_total.clone()))?;

        Ok(Self {
            inner: Arc::new(Inner {
                registry,
                forwarded_total,
                dropped_total,
                rate_limited_total,
                queue_full_total,
                challenge_issued_total,
                challenge_verified_total,
                fbs_frames_forwarded_total,
                fbs_frames_dropped_total,
                fbs_queue_full_total,
                udp_pkts_in_total,
                udp_pkts_forwarded_total,
                udp_dropped_total,
                udp_rate_limited_total,
                udp_queue_depth,
                udp_netio_recvmmsg_calls_total,
                udp_netio_recvmmsg_packets_total,
                udp_netio_sendmmsg_calls_total,
                udp_netio_sendmmsg_packets_total,
            }),
        })
    }

    pub fn record_forwarded(&self, direction: &'static str) {
        self.inner
            .forwarded_total
            .with_label_values(&[direction])
            .inc();
    }

    pub fn record_drop(&self, reason: &'static str) {
        self.inner.dropped_total.with_label_values(&[reason]).inc();
    }

    pub fn record_rate_limited(&self) {
        self.inner.rate_limited_total.inc();
    }

    pub fn record_queue_full(&self, direction: &'static str) {
        self.inner
            .queue_full_total
            .with_label_values(&[direction])
            .inc();
    }

    pub fn record_challenge_issued(&self) {
        self.inner.challenge_issued_total.inc();
    }

    pub fn record_challenge_verified(&self) {
        self.inner.challenge_verified_total.inc();
    }

    pub fn record_fbs_frame_forwarded(&self) {
        self.inner.fbs_frames_forwarded_total.inc();
    }

    pub fn record_fbs_frame_drop(&self, reason: &'static str) {
        self.inner
            .fbs_frames_dropped_total
            .with_label_values(&[reason])
            .inc();
    }

    pub fn record_fbs_queue_full(&self) {
        self.inner.fbs_queue_full_total.inc();
    }

    pub fn record_udp_packet_in(&self) {
        self.inner.udp_pkts_in_total.inc();
    }

    pub fn record_udp_packet_forwarded(&self) {
        self.inner.udp_pkts_forwarded_total.inc();
    }

    pub fn record_udp_drop(&self, reason: &'static str) {
        self.inner
            .udp_dropped_total
            .with_label_values(&[reason])
            .inc();
    }

    pub fn record_udp_rate_limited(&self, scope: &'static str) {
        self.inner
            .udp_rate_limited_total
            .with_label_values(&[scope])
            .inc();
    }

    pub fn set_udp_queue_depth(&self, direction: &'static str, lane: &'static str, depth: i64) {
        self.inner
            .udp_queue_depth
            .with_label_values(&[direction, lane])
            .set(depth);
    }

    pub fn record_udp_netio_recv_batch(&self, batch_size: usize) {
        self.inner.udp_netio_recvmmsg_calls_total.inc();
        self.inner
            .udp_netio_recvmmsg_packets_total
            .inc_by(batch_size as u64);
    }

    pub fn record_udp_netio_send_batch(&self, batch_size: usize) {
        self.inner.udp_netio_sendmmsg_calls_total.inc();
        self.inner
            .udp_netio_sendmmsg_packets_total
            .inc_by(batch_size as u64);
    }

    pub fn snapshot(&self) -> Result<String, MetricsError> {
        let metric_families = self.inner.registry.gather();
        let mut buf = Vec::new();
        TextEncoder::new().encode(&metric_families, &mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    pub fn spawn_exporter(
        &self,
        listen_addr: SocketAddr,
    ) -> Result<thread::JoinHandle<()>, MetricsError> {
        let server =
            Server::http(listen_addr).map_err(|err| MetricsError::Bind(err.to_string()))?;
        let registry = self.inner.registry.clone();

        Ok(thread::spawn(move || {
            let encoder = TextEncoder::new();
            for request in server.incoming_requests() {
                if request.method() != &Method::Get || request.url() != "/metrics" {
                    let response = Response::empty(StatusCode(404));
                    let _ = request.respond(response);
                    continue;
                }

                let gathered = registry.gather();
                let mut buffer = Vec::new();
                if encoder.encode(&gathered, &mut buffer).is_err() {
                    let response = Response::from_string("failed to encode metrics")
                        .with_status_code(StatusCode(500));
                    let _ = request.respond(response);
                    continue;
                }

                let response = Response::from_data(buffer).with_status_code(StatusCode(200));
                let _ = request.respond(response);
            }
        }))
    }
}
