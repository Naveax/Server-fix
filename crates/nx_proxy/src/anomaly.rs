use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::config::{AnomalyModel, AnomalySection, RateLimitSection};
#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
use std::path::Path;
#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
use tch::{CModule, Device, Kind, Tensor};

const MIN_ELAPSED_SECS: f64 = 1e-3;
const TORCH_SEQUENCE_LEN: usize = 10;
#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
const TORCH_INPUT_FEATURES: usize = 3;
#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
const PACKET_COUNT_SCALE: f32 = 1_024.0;
#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
const SIZE_AVG_SCALE: f32 = 1_500.0;
#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
const DELTA_SCALE: f32 = 1_024.0;

#[derive(Debug, Clone)]
struct RuntimeConfig {
    enabled: bool,
    threshold: f32,
    ddos_limit_pps: f64,
    ddos_limit_bps: f64,
    window: Duration,
    ema_alpha: f64,
    min_packets_per_window: u32,
    idle_timeout: Duration,
    max_tracked_ips: usize,
    model: AnomalyModel,
    #[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
    torch_model_path: Option<String>,
}

impl RuntimeConfig {
    fn from_sections(anomaly: &AnomalySection, rate_limit: &RateLimitSection) -> Self {
        Self {
            enabled: anomaly.enabled,
            threshold: anomaly.anomaly_threshold,
            ddos_limit_pps: anomaly.ddos_limit.max(1.0),
            ddos_limit_bps: rate_limit.per_ip_bytes_per_second.max(1.0),
            window: Duration::from_millis(anomaly.window_millis.max(1)),
            ema_alpha: anomaly.ema_alpha.clamp(0.01, 1.0),
            min_packets_per_window: anomaly.min_packets_per_window.max(1),
            idle_timeout: Duration::from_secs(anomaly.idle_timeout_secs.max(1)),
            max_tracked_ips: anomaly.max_tracked_ips.max(1),
            model: anomaly.model,
            #[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
            torch_model_path: anomaly.torch_model_path.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct PeerState {
    window_started: Instant,
    packet_count: u32,
    byte_count: usize,
    ema_pps: f64,
    ema_bps: f64,
    last_window_pps: f64,
    sequence_history: VecDeque<[f32; 3]>,
    last_seen: Instant,
}

impl PeerState {
    fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            packet_count: 0,
            byte_count: 0,
            ema_pps: 0.0,
            ema_bps: 0.0,
            last_window_pps: 0.0,
            sequence_history: VecDeque::with_capacity(TORCH_SEQUENCE_LEN),
            last_seen: now,
        }
    }

    fn observe(&mut self, packet_len: usize, now: Instant, cfg: &RuntimeConfig) {
        let elapsed = now.saturating_duration_since(self.window_started);
        if elapsed >= cfg.window {
            let secs = elapsed.as_secs_f64().max(MIN_ELAPSED_SECS);
            let packet_count = self.packet_count as f64;
            let size_avg = if self.packet_count > 0 {
                self.byte_count as f64 / self.packet_count as f64
            } else {
                0.0
            };
            let sample_pps = self.packet_count as f64 / secs;
            let sample_bps = self.byte_count as f64 / secs;
            let delta = if self.last_window_pps <= f64::EPSILON {
                0.0
            } else {
                sample_pps - self.last_window_pps
            };

            self.push_sequence_step([packet_count as f32, size_avg as f32, delta as f32]);
            self.last_window_pps = sample_pps;

            self.ema_pps = if self.ema_pps <= f64::EPSILON {
                sample_pps
            } else {
                (cfg.ema_alpha * sample_pps) + ((1.0 - cfg.ema_alpha) * self.ema_pps)
            };
            self.ema_bps = if self.ema_bps <= f64::EPSILON {
                sample_bps
            } else {
                (cfg.ema_alpha * sample_bps) + ((1.0 - cfg.ema_alpha) * self.ema_bps)
            };

            self.window_started = now;
            self.packet_count = 0;
            self.byte_count = 0;
        }

        self.packet_count = self.packet_count.saturating_add(1);
        self.byte_count = self.byte_count.saturating_add(packet_len);
        self.last_seen = now;
    }

    fn push_sequence_step(&mut self, step: [f32; 3]) {
        if self.sequence_history.len() >= TORCH_SEQUENCE_LEN {
            let _ = self.sequence_history.pop_front();
        }
        self.sequence_history.push_back(step);
    }

    fn heuristic_features(&self, now: Instant, cfg: &RuntimeConfig) -> [f32; 3] {
        let elapsed = now
            .saturating_duration_since(self.window_started)
            .as_secs_f64()
            .max(MIN_ELAPSED_SECS);
        let instant_pps = self.packet_count as f64 / elapsed;
        let instant_bps = self.byte_count as f64 / elapsed;
        let ema_pps = self.ema_pps.max(1.0);

        let ddos_ratio = (instant_pps / cfg.ddos_limit_pps).clamp(0.0, 32.0);
        let jump_ratio = (instant_pps / ema_pps).clamp(0.0, 32.0);
        let byte_ratio = (instant_bps / cfg.ddos_limit_bps).clamp(0.0, 32.0);
        [ddos_ratio as f32, jump_ratio as f32, byte_ratio as f32]
    }

    fn current_sequence_step(&self, now: Instant) -> [f32; 3] {
        let elapsed = now
            .saturating_duration_since(self.window_started)
            .as_secs_f64()
            .max(MIN_ELAPSED_SECS);
        let packet_count = self.packet_count as f64;
        let size_avg = if self.packet_count > 0 {
            self.byte_count as f64 / self.packet_count as f64
        } else {
            0.0
        };
        let pps = packet_count / elapsed;
        let delta = if self.last_window_pps <= f64::EPSILON {
            0.0
        } else {
            pps - self.last_window_pps
        };
        [packet_count as f32, size_avg as f32, delta as f32]
    }

    fn sequence_window(&self, now: Instant) -> Vec<[f32; 3]> {
        let mut sequence = self
            .sequence_history
            .iter()
            .copied()
            .collect::<Vec<[f32; 3]>>();
        sequence.push(self.current_sequence_step(now));
        if sequence.len() > TORCH_SEQUENCE_LEN {
            sequence.drain(0..(sequence.len() - TORCH_SEQUENCE_LEN));
        }
        sequence
    }
}

#[derive(Debug)]
struct BoundedPeerStore {
    entries: HashMap<IpAddr, PeerState>,
    lru: VecDeque<IpAddr>,
    capacity: usize,
    idle_timeout: Duration,
}

impl BoundedPeerStore {
    fn new(capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            lru: VecDeque::new(),
            capacity: capacity.max(1),
            idle_timeout,
        }
    }

    fn get_or_insert(&mut self, key: IpAddr, now: Instant) -> &mut PeerState {
        self.gc_idle(now);
        if !self.entries.contains_key(&key) {
            self.evict_if_full();
            self.entries.insert(key, PeerState::new(now));
        }
        self.lru.push_back(key);
        self.entries
            .get_mut(&key)
            .expect("entry must exist after insertion")
    }

    fn evict_if_full(&mut self) {
        while self.entries.len() >= self.capacity {
            let Some(candidate) = self.lru.pop_front() else {
                break;
            };
            if self.entries.remove(&candidate).is_some() {
                break;
            }
        }
    }

    fn gc_idle(&mut self, now: Instant) {
        self.entries
            .retain(|_, peer| now.saturating_duration_since(peer.last_seen) <= self.idle_timeout);
        self.lru.retain(|ip| self.entries.contains_key(ip));
        self.compact_lru_if_needed();
    }

    fn compact_lru_if_needed(&mut self) {
        let cap = self.capacity.saturating_mul(8).max(128);
        if self.lru.len() <= cap {
            return;
        }

        let mut seen = HashSet::with_capacity(self.entries.len());
        let mut compacted = VecDeque::with_capacity(self.entries.len());
        while let Some(ip) = self.lru.pop_back() {
            if self.entries.contains_key(&ip) && seen.insert(ip) {
                compacted.push_front(ip);
            }
        }
        self.lru = compacted;
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn lru_len(&self) -> usize {
        self.lru.len()
    }
}

pub struct AnomalyDetector {
    cfg: RuntimeConfig,
    peers: BoundedPeerStore,
    #[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
    torch: Option<TorchRuntime>,
}

impl AnomalyDetector {
    pub fn new(anomaly: &AnomalySection, rate_limit: &RateLimitSection) -> Self {
        let cfg = RuntimeConfig::from_sections(anomaly, rate_limit);
        let peers = BoundedPeerStore::new(cfg.max_tracked_ips, cfg.idle_timeout);
        #[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
        let torch = if cfg.enabled && cfg.model == AnomalyModel::Torch {
            cfg.torch_model_path
                .as_deref()
                .and_then(TorchRuntime::try_load)
        } else {
            None
        };

        Self {
            cfg,
            peers,
            #[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
            torch,
        }
    }

    pub fn should_drop(&mut self, source_ip: IpAddr, packet_len: usize) -> Option<f32> {
        self.should_drop_at(source_ip, packet_len, Instant::now())
    }

    pub fn check_anomaly(
        &mut self,
        source_ip: IpAddr,
        packet_len: usize,
        now: Instant,
    ) -> Option<f32> {
        self.should_drop_at(source_ip, packet_len, now)
    }

    pub fn check_anomaly_score(
        &mut self,
        source_ip: IpAddr,
        packet_len: usize,
        now: Instant,
    ) -> Option<f32> {
        self.score_at(source_ip, packet_len, now)
    }

    pub(crate) fn should_drop_at(
        &mut self,
        source_ip: IpAddr,
        packet_len: usize,
        now: Instant,
    ) -> Option<f32> {
        let score = self.score_at(source_ip, packet_len, now)?;
        if score >= self.cfg.threshold {
            Some(score)
        } else {
            None
        }
    }

    fn score_at(&mut self, source_ip: IpAddr, packet_len: usize, now: Instant) -> Option<f32> {
        if !self.cfg.enabled {
            return None;
        }

        let (features, sequence, warmed_up) = {
            let peer = self.peers.get_or_insert(source_ip, now);
            peer.observe(packet_len, now, &self.cfg);
            let warmed_up =
                peer.packet_count >= self.cfg.min_packets_per_window || peer.ema_pps > f64::EPSILON;
            let features = peer.heuristic_features(now, &self.cfg);
            let sequence = peer.sequence_window(now);
            (features, sequence, warmed_up)
        };
        if !warmed_up {
            return None;
        }

        Some(self.score_features(features, &sequence))
    }

    fn score_features(&self, features: [f32; 3], sequence: &[[f32; 3]]) -> f32 {
        match self.cfg.model {
            AnomalyModel::Heuristic => heuristic_score(features),
            AnomalyModel::Torch => self
                .torch_score(sequence)
                .unwrap_or_else(|| heuristic_score(features)),
        }
    }

    #[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
    fn torch_score(&self, sequence: &[[f32; 3]]) -> Option<f32> {
        self.torch.as_ref()?.infer_score(sequence)
    }

    #[cfg(any(
        not(feature = "torch_anomaly"),
        all(feature = "torch_anomaly", debug_assertions)
    ))]
    fn torch_score(&self, _sequence: &[[f32; 3]]) -> Option<f32> {
        None
    }

    #[cfg(test)]
    fn tracked_ip_count(&self) -> usize {
        self.peers.len()
    }

    #[cfg(test)]
    fn lru_len(&self) -> usize {
        self.peers.lru_len()
    }
}

fn heuristic_score(features: [f32; 3]) -> f32 {
    let z = (1.8 * features[0]) + (1.1 * features[1]) + (0.9 * features[2]) - 3.1;
    1.0 / (1.0 + (-z).exp())
}

#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
struct TorchRuntime {
    module: CModule,
    device: Device,
}

#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
impl TorchRuntime {
    fn try_load(path: &str) -> Option<Self> {
        let path_ref = Path::new(path);
        let device = preferred_torch_device();
        match CModule::load_on_device(path_ref, device) {
            Ok(module) => Some(Self { module, device }),
            Err(err) => {
                eprintln!(
                    "nx_proxy anomaly torch model load failed for {}: {}",
                    path_ref.display(),
                    err
                );
                None
            }
        }
    }

    fn infer_score(&self, sequence: &[[f32; 3]]) -> Option<f32> {
        let mut flat = vec![0.0_f32; TORCH_SEQUENCE_LEN * TORCH_INPUT_FEATURES];
        let take = sequence.len().min(TORCH_SEQUENCE_LEN);
        let start = TORCH_SEQUENCE_LEN.saturating_sub(take);
        let tail = &sequence[sequence.len().saturating_sub(take)..];
        for (i, step) in tail.iter().enumerate() {
            let base = (start + i) * TORCH_INPUT_FEATURES;
            let normalized = normalize_sequence_step(*step);
            flat[base..base + TORCH_INPUT_FEATURES].copy_from_slice(&normalized);
        }

        // Expected TorchScript input for LSTM/autoencoder style models: [batch=1, seq=10, feat=3].
        let input = Tensor::f_from_slice(&flat)
            .ok()?
            .to_device(self.device)
            .to_kind(Kind::Float)
            .reshape([1, TORCH_SEQUENCE_LEN as i64, TORCH_INPUT_FEATURES as i64]);
        let output = self.module.forward_ts(&[input]).ok()?;

        let flat_output = output.flatten(0, -1).to_kind(Kind::Float);
        if flat_output.numel() < 1 {
            return None;
        }
        let score = if flat_output.numel() == 1 {
            let raw = flat_output.double_value(&[0]) as f32;
            if !raw.is_finite() {
                return None;
            }
            if (0.0..=1.0).contains(&raw) {
                raw
            } else {
                logistic_score(raw)
            }
        } else {
            // Autoencoder-style fallback: map reconstruction magnitude to [0, 1].
            let recon = flat_output.abs().mean(Kind::Float).double_value(&[]) as f32;
            if !recon.is_finite() {
                return None;
            }
            (1.0 - (-recon).exp()).clamp(0.0, 1.0)
        };
        Some(score.clamp(0.0, 1.0))
    }
}

#[cfg(all(
    feature = "torch_anomaly",
    not(debug_assertions),
    feature = "cuda_anomaly"
))]
fn preferred_torch_device() -> Device {
    if tch::Cuda::is_available() {
        Device::Cuda(0)
    } else {
        Device::Cpu
    }
}

#[cfg(all(
    feature = "torch_anomaly",
    not(debug_assertions),
    not(feature = "cuda_anomaly")
))]
fn preferred_torch_device() -> Device {
    Device::Cpu
}

#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
fn normalize_sequence_step(step: [f32; 3]) -> [f32; 3] {
    [
        (step[0] / PACKET_COUNT_SCALE).clamp(0.0, 8.0),
        (step[1] / SIZE_AVG_SCALE).clamp(0.0, 2.0),
        (step[2] / DELTA_SCALE).clamp(-8.0, 8.0),
    ]
}

#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
fn logistic_score(v: f32) -> f32 {
    1.0 / (1.0 + (-v).exp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AnomalySection, RateLimitSection};
    use std::net::Ipv4Addr;

    fn rate_limit_fixture() -> RateLimitSection {
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
            max_ip_buckets: 128,
            max_subnet_buckets: 64,
            idle_timeout_secs: 60,
        }
    }

    #[test]
    fn disabled_detector_allows_traffic() {
        let anomaly = AnomalySection {
            enabled: false,
            ..AnomalySection::default()
        };
        let mut detector = AnomalyDetector::new(&anomaly, &rate_limit_fixture());
        let now = Instant::now();

        for i in 0..100 {
            let drop = detector.should_drop_at(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                512,
                now + Duration::from_millis(i),
            );
            assert!(drop.is_none());
        }
    }

    #[test]
    fn detects_packet_spike() {
        let anomaly = AnomalySection {
            enabled: true,
            ddos_limit: 20.0,
            anomaly_threshold: 0.8,
            min_packets_per_window: 5,
            window_millis: 200,
            ..AnomalySection::default()
        };

        let mut detector = AnomalyDetector::new(&anomaly, &rate_limit_fixture());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
        let base = Instant::now();

        let mut dropped = false;
        for i in 0..200 {
            let now = base + Duration::from_millis(i / 10);
            if detector.should_drop_at(ip, 400, now).is_some() {
                dropped = true;
                break;
            }
        }
        assert!(dropped, "spike traffic should be flagged");
    }

    #[test]
    fn tracked_peers_stay_bounded_under_churn() {
        let anomaly = AnomalySection {
            enabled: true,
            max_tracked_ips: 32,
            idle_timeout_secs: 1,
            ..AnomalySection::default()
        };

        let mut detector = AnomalyDetector::new(&anomaly, &rate_limit_fixture());
        let base = Instant::now();
        for i in 0..10_000_u32 {
            let octet = (i % 250) as u8;
            let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 10, octet));
            let now = base + Duration::from_millis(i as u64);
            let _ = detector.should_drop_at(ip, 100, now);
        }

        assert!(detector.tracked_ip_count() <= 32);
        let cap = 32usize.saturating_mul(8).max(128);
        assert!(detector.lru_len() <= cap);
    }
}
