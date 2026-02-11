use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::config::{MmrModel, MmrSection};
#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
use std::path::Path;
#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
use tch::{CModule, Device, Kind, Tensor};

const MIN_ELAPSED_SECS: f64 = 1e-3;
const MMR_HISTORY_CAPACITY: usize = 16;
#[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
const TORCH_FEATURES: usize = 3;

#[derive(Debug, Clone)]
struct RuntimeConfig {
    enabled: bool,
    threshold: f32,
    window: Duration,
    idle_timeout: Duration,
    max_tracked_ips: usize,
    model: MmrModel,
    #[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
    torch_model_path: Option<String>,
}

impl RuntimeConfig {
    fn from_section(section: &MmrSection) -> Self {
        Self {
            enabled: section.enabled,
            threshold: section.mmr_threshold,
            window: Duration::from_secs(section.window_secs.max(1)),
            idle_timeout: Duration::from_secs(section.idle_timeout_secs.max(1)),
            max_tracked_ips: section.max_tracked_ips.max(1),
            model: section.model,
            #[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
            torch_model_path: section.torch_model_path.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct PeerState {
    last_mmr: Option<f32>,
    last_update: Instant,
    ema_abs_delta: f64,
    delta_history: VecDeque<f32>,
    last_seen: Instant,
}

impl PeerState {
    fn new(now: Instant) -> Self {
        Self {
            last_mmr: None,
            last_update: now,
            ema_abs_delta: 0.0,
            delta_history: VecDeque::with_capacity(MMR_HISTORY_CAPACITY),
            last_seen: now,
        }
    }

    fn observe(&mut self, mmr: f32, now: Instant, cfg: &RuntimeConfig) -> Option<[f32; 3]> {
        let previous = self.last_mmr?;
        let elapsed = now
            .saturating_duration_since(self.last_update)
            .as_secs_f64()
            .max(MIN_ELAPSED_SECS);
        let abs_delta = (mmr - previous).abs() as f64;
        let velocity = abs_delta / elapsed;

        self.ema_abs_delta = if self.ema_abs_delta <= f64::EPSILON {
            abs_delta
        } else {
            // Use window-derived smoothing to avoid over-reacting to one sample.
            let alpha = (elapsed / cfg.window.as_secs_f64().max(1.0)).clamp(0.05, 1.0);
            (alpha * abs_delta) + ((1.0 - alpha) * self.ema_abs_delta)
        };

        if self.delta_history.len() >= MMR_HISTORY_CAPACITY {
            let _ = self.delta_history.pop_front();
        }
        self.delta_history.push_back(abs_delta as f32);

        self.last_mmr = Some(mmr);
        self.last_update = now;
        self.last_seen = now;

        let volatility = rolling_stddev(&self.delta_history) as f64;
        let delta_ratio = (abs_delta / 120.0).clamp(0.0, 8.0);
        let velocity_ratio = (velocity / 60.0).clamp(0.0, 8.0);
        let volatility_ratio = (volatility / 100.0).clamp(0.0, 8.0);

        Some([
            delta_ratio as f32,
            velocity_ratio as f32,
            volatility_ratio as f32,
        ])
    }

    fn seed(&mut self, mmr: f32, now: Instant) {
        self.last_mmr = Some(mmr);
        self.last_update = now;
        self.last_seen = now;
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

    fn get_or_insert(&mut self, ip: IpAddr, now: Instant) -> &mut PeerState {
        self.gc_idle(now);
        if !self.entries.contains_key(&ip) {
            self.evict_if_full();
            self.entries.insert(ip, PeerState::new(now));
        }
        self.lru.push_back(ip);
        self.entries
            .get_mut(&ip)
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

pub struct MmrDetector {
    cfg: RuntimeConfig,
    peers: BoundedPeerStore,
    #[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
    torch: Option<TorchRuntime>,
}

impl MmrDetector {
    pub fn new(section: &MmrSection) -> Self {
        let cfg = RuntimeConfig::from_section(section);
        let peers = BoundedPeerStore::new(cfg.max_tracked_ips, cfg.idle_timeout);
        #[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
        let torch = if cfg.enabled && cfg.model == MmrModel::Torch {
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

    pub fn check_smurf_with_payload(
        &mut self,
        source_ip: IpAddr,
        payload: &[u8],
        now: Instant,
    ) -> Option<f32> {
        if !self.cfg.enabled {
            return None;
        }

        let mmr = parse_mmr_sample(payload)?;
        let features = {
            let peer = self.peers.get_or_insert(source_ip, now);
            if peer.last_mmr.is_none() {
                peer.seed(mmr, now);
                return None;
            }
            peer.observe(mmr, now, &self.cfg)?
        };

        let score = self.score_features(features);
        if score >= self.cfg.threshold {
            Some(score)
        } else {
            None
        }
    }

    fn score_features(&self, features: [f32; 3]) -> f32 {
        match self.cfg.model {
            MmrModel::Heuristic => heuristic_score(features),
            MmrModel::Torch => self
                .torch_score(features)
                .unwrap_or_else(|| heuristic_score(features)),
        }
    }

    #[cfg(all(feature = "torch_anomaly", not(debug_assertions)))]
    fn torch_score(&self, features: [f32; 3]) -> Option<f32> {
        self.torch.as_ref()?.infer_score(features)
    }

    #[cfg(any(
        not(feature = "torch_anomaly"),
        all(feature = "torch_anomaly", debug_assertions)
    ))]
    fn torch_score(&self, _features: [f32; 3]) -> Option<f32> {
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

pub fn parse_mmr_sample(payload: &[u8]) -> Option<f32> {
    let marker = b"MMR:";
    let start = payload
        .windows(marker.len())
        .position(|window| window == marker)?;
    let value_start = start + marker.len();
    let tail = &payload[value_start..];
    let value_end = tail
        .iter()
        .position(|byte| !matches!(byte, b'0'..=b'9' | b'.' | b'+' | b'-'))
        .unwrap_or(tail.len());
    if value_end == 0 {
        return None;
    }
    std::str::from_utf8(&tail[..value_end])
        .ok()?
        .parse::<f32>()
        .ok()
}

fn rolling_stddev(values: &VecDeque<f32>) -> f32 {
    if values.is_empty() {
        return 0.0;
    }
    let mean = values.iter().map(|v| *v as f64).sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|v| {
            let d = (*v as f64) - mean;
            d * d
        })
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt() as f32
}

fn heuristic_score(features: [f32; 3]) -> f32 {
    let z = (2.0 * features[0]) + (1.5 * features[1]) + (1.0 * features[2]) - 3.2;
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
        let device = Device::Cpu;
        match CModule::load_on_device(path_ref, device) {
            Ok(module) => Some(Self { module, device }),
            Err(err) => {
                eprintln!(
                    "nx_proxy mmr torch model load failed for {}: {}",
                    path_ref.display(),
                    err
                );
                None
            }
        }
    }

    fn infer_score(&self, features: [f32; 3]) -> Option<f32> {
        let input = Tensor::f_from_slice(&features)
            .ok()?
            .to_device(self.device)
            .to_kind(Kind::Float)
            .reshape([1, TORCH_FEATURES as i64]);
        let output = self.module.forward_ts(&[input]).ok()?;
        let score = output.flatten(0, -1).double_value(&[0]) as f32;
        if !score.is_finite() {
            return None;
        }
        if (0.0..=1.0).contains(&score) {
            Some(score)
        } else {
            Some(1.0 / (1.0 + (-score).exp()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_mmr_sample_from_payload() {
        let payload = b"STAT|MMR:1462.5|SYNC:17";
        let mmr = parse_mmr_sample(payload).expect("must parse");
        assert!((mmr - 1462.5).abs() < f32::EPSILON);
    }

    #[test]
    fn detects_unusual_mmr_swings() {
        let mut detector = MmrDetector::new(&MmrSection {
            enabled: true,
            mmr_threshold: 0.7,
            ..MmrSection::default()
        });
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let base = Instant::now();

        let _ = detector.check_smurf_with_payload(ip, b"MMR:1200", base);
        let dropped =
            detector.check_smurf_with_payload(ip, b"MMR:1700", base + Duration::from_millis(200));
        assert!(dropped.is_some(), "large swings should be detected");
    }

    #[test]
    fn ignores_small_mmr_drift() {
        let mut detector = MmrDetector::new(&MmrSection {
            enabled: true,
            mmr_threshold: 0.85,
            ..MmrSection::default()
        });
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        let base = Instant::now();

        let _ = detector.check_smurf_with_payload(ip, b"MMR:1200", base);
        let decision =
            detector.check_smurf_with_payload(ip, b"MMR:1205", base + Duration::from_secs(30));
        assert!(decision.is_none(), "small drift should pass");
    }

    #[test]
    fn tracked_peers_stay_bounded_under_churn() {
        let mut detector = MmrDetector::new(&MmrSection {
            enabled: true,
            max_tracked_ips: 32,
            idle_timeout_secs: 1,
            ..MmrSection::default()
        });
        let base = Instant::now();

        for i in 0..10_000_u32 {
            let ip = IpAddr::V4(Ipv4Addr::new(172, 18, 0, (i % 240) as u8));
            let now = base + Duration::from_millis(i as u64);
            let payload = if i % 2 == 0 { b"MMR:1300" } else { b"MMR:1390" };
            let _ = detector.check_smurf_with_payload(ip, payload, now);
        }

        assert!(detector.tracked_ip_count() <= 32);
        let cap = 32usize.saturating_mul(8).max(128);
        assert!(detector.lru_len() <= cap);
    }
}
