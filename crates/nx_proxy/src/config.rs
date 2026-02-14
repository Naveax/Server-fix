use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub proxy: ProxySection,
    pub rate_limit: RateLimitSection,
    #[serde(default)]
    pub packet_validation: PacketValidationSection,
    #[serde(default)]
    pub anomaly: AnomalySection,
    #[serde(default)]
    pub mmr: MmrSection,
    #[serde(default)]
    pub flood_sim: FloodSimSection,
    #[serde(default, alias = "challenge")]
    pub cookie: CookieSection,
    pub metrics: MetricsSection,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxySection {
    pub listen_addr: SocketAddr,
    pub upstream_addr: SocketAddr,
    #[serde(default = "default_worker_count")]
    pub worker_count: usize,
    #[serde(default = "default_true")]
    pub reuse_port: bool,
    #[serde(default)]
    pub pin_workers: bool,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "default_min_datagram_bytes")]
    pub min_datagram_bytes: usize,
    #[serde(default = "default_max_datagram_bytes")]
    pub max_datagram_bytes: usize,
    #[serde(default = "default_true")]
    pub drop_udp_fragments: bool,
    #[serde(default = "default_legacy_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default)]
    pub telemetry_queue_capacity: Option<usize>,
    #[serde(default)]
    pub critical_queue_capacity: Option<usize>,
    /// Optional: downstream (upstream->client) telemetry queue capacity override.
    /// If unset, falls back to `telemetry_queue_capacity` then `queue_capacity`.
    #[serde(default)]
    pub downstream_telemetry_queue_capacity: Option<usize>,
    /// Optional: downstream (upstream->client) critical queue capacity override.
    /// If unset, falls back to `critical_queue_capacity` then `queue_capacity`.
    #[serde(default)]
    pub downstream_critical_queue_capacity: Option<usize>,
    #[serde(default)]
    pub critical_overflow_policy: CriticalOverflowPolicy,
    #[serde(default = "default_critical_block_timeout_millis")]
    pub critical_block_timeout_millis: u64,
    // Optional load-shedding: if packets sit in the downstream queue too long, drop them
    // instead of delivering stale data to clients. 0 disables.
    #[serde(default)]
    pub downstream_telemetry_ttl_millis: u64,
    #[serde(default)]
    pub downstream_critical_ttl_millis: u64,
    #[serde(default)]
    pub telemetry_prefixes: Vec<String>,
    /// Optional: override telemetry classification per direction.
    /// If empty, falls back to `telemetry_prefixes`.
    #[serde(default)]
    pub telemetry_prefixes_upstream: Vec<String>,
    /// Optional: override telemetry classification per direction.
    /// If empty, falls back to `telemetry_prefixes`.
    #[serde(default)]
    pub telemetry_prefixes_downstream: Vec<String>,
}

impl ProxySection {
    pub fn telemetry_queue_capacity(&self) -> usize {
        self.telemetry_queue_capacity
            .unwrap_or(self.queue_capacity)
            .max(1)
    }

    pub fn critical_queue_capacity(&self) -> usize {
        self.critical_queue_capacity
            .unwrap_or(self.queue_capacity)
            .max(1)
    }

    pub fn downstream_telemetry_queue_capacity(&self) -> usize {
        self.downstream_telemetry_queue_capacity
            .or(self.telemetry_queue_capacity)
            .unwrap_or(self.queue_capacity)
            .max(1)
    }

    pub fn downstream_critical_queue_capacity(&self) -> usize {
        self.downstream_critical_queue_capacity
            .or(self.critical_queue_capacity)
            .unwrap_or(self.queue_capacity)
            .max(1)
    }

    pub fn telemetry_prefix_bytes(&self) -> Vec<Vec<u8>> {
        prefix_bytes(&self.telemetry_prefixes)
    }

    pub fn telemetry_prefix_bytes_upstream(&self) -> Vec<Vec<u8>> {
        if self.telemetry_prefixes_upstream.is_empty() {
            self.telemetry_prefix_bytes()
        } else {
            prefix_bytes(&self.telemetry_prefixes_upstream)
        }
    }

    pub fn telemetry_prefix_bytes_downstream(&self) -> Vec<Vec<u8>> {
        if self.telemetry_prefixes_downstream.is_empty() {
            self.telemetry_prefix_bytes()
        } else {
            prefix_bytes(&self.telemetry_prefixes_downstream)
        }
    }
}

fn prefix_bytes(prefixes: &[String]) -> Vec<Vec<u8>> {
    prefixes
        .iter()
        .filter(|prefix| !prefix.is_empty())
        .map(|prefix| prefix.as_bytes().to_vec())
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitSection {
    #[serde(
        default = "default_per_ip_packets_per_second",
        alias = "packets_per_second",
        alias = "ddos_limit"
    )]
    pub per_ip_packets_per_second: f64,
    #[serde(default = "default_per_ip_burst_packets", alias = "burst_packets")]
    pub per_ip_burst_packets: f64,
    #[serde(
        default = "default_per_ip_bytes_per_second",
        alias = "bytes_per_second"
    )]
    pub per_ip_bytes_per_second: f64,
    #[serde(default = "default_per_ip_burst_bytes", alias = "burst_bytes")]
    pub per_ip_burst_bytes: f64,
    #[serde(default = "default_global_packets_per_second")]
    pub global_packets_per_second: f64,
    #[serde(default = "default_global_burst_packets")]
    pub global_burst_packets: f64,
    #[serde(default = "default_global_bytes_per_second")]
    pub global_bytes_per_second: f64,
    #[serde(default = "default_global_burst_bytes")]
    pub global_burst_bytes: f64,
    #[serde(default)]
    pub subnet_enabled: bool,
    #[serde(default = "default_subnet_ipv4_prefix")]
    pub subnet_ipv4_prefix: u8,
    #[serde(default = "default_subnet_ipv6_prefix")]
    pub subnet_ipv6_prefix: u8,
    #[serde(default = "default_subnet_packets_per_second")]
    pub subnet_packets_per_second: f64,
    #[serde(default = "default_subnet_burst_packets")]
    pub subnet_burst_packets: f64,
    #[serde(default = "default_subnet_bytes_per_second")]
    pub subnet_bytes_per_second: f64,
    #[serde(default = "default_subnet_burst_bytes")]
    pub subnet_burst_bytes: f64,
    #[serde(default = "default_max_ip_buckets")]
    pub max_ip_buckets: usize,
    #[serde(default = "default_max_subnet_buckets")]
    pub max_subnet_buckets: usize,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnomalySection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub model: AnomalyModel,
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: f32,
    #[serde(default = "default_per_ip_packets_per_second")]
    pub ddos_limit: f64,
    #[serde(default = "default_anomaly_window_millis")]
    pub window_millis: u64,
    #[serde(default = "default_anomaly_ema_alpha")]
    pub ema_alpha: f64,
    #[serde(default = "default_anomaly_min_packets")]
    pub min_packets_per_window: u32,
    #[serde(default = "default_anomaly_max_tracked_ips")]
    pub max_tracked_ips: usize,
    #[serde(default = "default_anomaly_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub client_sync_check: bool,
    #[serde(default = "default_client_sync_threshold_ms")]
    pub client_sync_threshold_ms: f32,
    #[serde(default = "default_client_sync_weight")]
    pub client_sync_weight: f32,
    #[serde(default)]
    pub torch_model_path: Option<String>,
}

impl Default for AnomalySection {
    fn default() -> Self {
        Self {
            enabled: false,
            model: AnomalyModel::default(),
            anomaly_threshold: default_anomaly_threshold(),
            ddos_limit: default_per_ip_packets_per_second(),
            window_millis: default_anomaly_window_millis(),
            ema_alpha: default_anomaly_ema_alpha(),
            min_packets_per_window: default_anomaly_min_packets(),
            max_tracked_ips: default_anomaly_max_tracked_ips(),
            idle_timeout_secs: default_anomaly_idle_timeout_secs(),
            client_sync_check: false,
            client_sync_threshold_ms: default_client_sync_threshold_ms(),
            client_sync_weight: default_client_sync_weight(),
            torch_model_path: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PacketValidationSection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub strict_mode: bool,
    #[serde(default)]
    pub require_checksum: bool,
    #[serde(default)]
    pub strip_checksum_header: bool,
}

impl Default for PacketValidationSection {
    fn default() -> Self {
        Self {
            enabled: false,
            strict_mode: true,
            require_checksum: false,
            strip_checksum_header: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MmrSection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub model: MmrModel,
    #[serde(default = "default_mmr_threshold")]
    pub mmr_threshold: f32,
    #[serde(default = "default_mmr_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_mmr_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_mmr_max_tracked_ips")]
    pub max_tracked_ips: usize,
    #[serde(default)]
    pub torch_model_path: Option<String>,
}

impl Default for MmrSection {
    fn default() -> Self {
        Self {
            enabled: false,
            model: MmrModel::default(),
            mmr_threshold: default_mmr_threshold(),
            window_secs: default_mmr_window_secs(),
            idle_timeout_secs: default_mmr_idle_timeout_secs(),
            max_tracked_ips: default_mmr_max_tracked_ips(),
            torch_model_path: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FloodSimSection {
    #[serde(default)]
    pub allow_non_local: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CookieSection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: CookieMode,
    #[serde(default = "default_cookie_secret")]
    pub secret: String,
    #[serde(default = "default_cookie_ttl")]
    pub token_ttl_secs: u64,
    #[serde(default = "default_cookie_tag_bytes")]
    pub tag_bytes: usize,
    #[serde(default = "default_cookie_max_peers")]
    pub max_tracked_peers: usize,
    #[serde(default = "default_cookie_challenge_pps")]
    pub challenge_packets_per_second: f64,
    #[serde(default = "default_cookie_challenge_burst")]
    pub challenge_burst_packets: f64,
}

impl Default for CookieSection {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: CookieMode::default(),
            secret: default_cookie_secret(),
            token_ttl_secs: default_cookie_ttl(),
            tag_bytes: default_cookie_tag_bytes(),
            max_tracked_peers: default_cookie_max_peers(),
            challenge_packets_per_second: default_cookie_challenge_pps(),
            challenge_burst_packets: default_cookie_challenge_burst(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsSection {
    #[serde(default)]
    pub enabled: bool,
    pub listen_addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CriticalOverflowPolicy {
    DropNewest,
    #[default]
    DropOldest,
    BlockWithTimeout,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CookieMode {
    #[default]
    Strict,
    Compat,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyModel {
    #[default]
    Heuristic,
    Torch,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MmrModel {
    #[default]
    Heuristic,
    Torch,
}

fn default_true() -> bool {
    true
}

fn default_worker_count() -> usize {
    1
}

fn default_batch_size() -> usize {
    32
}

fn default_max_sessions() -> usize {
    65_536
}

fn default_min_datagram_bytes() -> usize {
    1
}

fn default_max_datagram_bytes() -> usize {
    1400
}

fn default_legacy_queue_capacity() -> usize {
    256
}

fn default_critical_block_timeout_millis() -> u64 {
    5
}

fn default_idle_timeout_secs() -> u64 {
    300
}

fn default_per_ip_packets_per_second() -> f64 {
    500.0
}

fn default_per_ip_burst_packets() -> f64 {
    1_000.0
}

fn default_per_ip_bytes_per_second() -> f64 {
    500_000.0
}

fn default_per_ip_burst_bytes() -> f64 {
    1_000_000.0
}

fn default_global_packets_per_second() -> f64 {
    20_000.0
}

fn default_global_burst_packets() -> f64 {
    40_000.0
}

fn default_global_bytes_per_second() -> f64 {
    128_000_000.0
}

fn default_global_burst_bytes() -> f64 {
    256_000_000.0
}

fn default_subnet_ipv4_prefix() -> u8 {
    24
}

fn default_subnet_ipv6_prefix() -> u8 {
    64
}

fn default_subnet_packets_per_second() -> f64 {
    8_000.0
}

fn default_subnet_burst_packets() -> f64 {
    16_000.0
}

fn default_subnet_bytes_per_second() -> f64 {
    64_000_000.0
}

fn default_subnet_burst_bytes() -> f64 {
    128_000_000.0
}

fn default_max_ip_buckets() -> usize {
    65_536
}

fn default_max_subnet_buckets() -> usize {
    16_384
}

fn default_anomaly_threshold() -> f32 {
    0.80
}

fn default_anomaly_window_millis() -> u64 {
    200
}

fn default_anomaly_ema_alpha() -> f64 {
    0.35
}

fn default_anomaly_min_packets() -> u32 {
    12
}

fn default_anomaly_max_tracked_ips() -> usize {
    65_536
}

fn default_anomaly_idle_timeout_secs() -> u64 {
    120
}

fn default_client_sync_threshold_ms() -> f32 {
    120.0
}

fn default_client_sync_weight() -> f32 {
    0.35
}

fn default_mmr_threshold() -> f32 {
    0.80
}

fn default_mmr_window_secs() -> u64 {
    30
}

fn default_mmr_idle_timeout_secs() -> u64 {
    600
}

fn default_mmr_max_tracked_ips() -> usize {
    65_536
}

fn default_cookie_secret() -> String {
    "replace-me".to_string()
}

fn default_cookie_ttl() -> u64 {
    20
}

fn default_cookie_tag_bytes() -> usize {
    16
}

fn default_cookie_max_peers() -> usize {
    65_536
}

fn default_cookie_challenge_pps() -> f64 {
    5_000.0
}

fn default_cookie_challenge_burst() -> f64 {
    10_000.0
}

impl ProxyConfig {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed reading config file {}", path.display()))?;
        let cfg = Self::from_toml(&raw).with_context(|| "invalid config file")?;
        Ok(cfg)
    }

    pub fn from_toml(raw: &str) -> Result<Self> {
        let cfg: ProxyConfig = toml::from_str(raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.proxy.worker_count == 0 {
            bail!("proxy.worker_count must be > 0");
        }
        if self.proxy.batch_size == 0 {
            bail!("proxy.batch_size must be > 0");
        }
        if self.proxy.max_sessions == 0 {
            bail!("proxy.max_sessions must be > 0");
        }
        if self.proxy.min_datagram_bytes > self.proxy.max_datagram_bytes {
            bail!("proxy.min_datagram_bytes must be <= proxy.max_datagram_bytes");
        }
        if self.proxy.queue_capacity == 0 {
            bail!("proxy.queue_capacity must be > 0");
        }
        if self.proxy.telemetry_queue_capacity() == 0 {
            bail!("proxy.telemetry_queue_capacity must be > 0");
        }
        if self.proxy.critical_queue_capacity() == 0 {
            bail!("proxy.critical_queue_capacity must be > 0");
        }

        if self.rate_limit.per_ip_packets_per_second <= 0.0
            || self.rate_limit.per_ip_bytes_per_second <= 0.0
            || self.rate_limit.per_ip_burst_packets <= 0.0
            || self.rate_limit.per_ip_burst_bytes <= 0.0
            || self.rate_limit.global_packets_per_second <= 0.0
            || self.rate_limit.global_bytes_per_second <= 0.0
            || self.rate_limit.global_burst_packets <= 0.0
            || self.rate_limit.global_burst_bytes <= 0.0
        {
            bail!("rate_limit values must be positive");
        }

        if self.rate_limit.subnet_enabled
            && (self.rate_limit.subnet_packets_per_second <= 0.0
                || self.rate_limit.subnet_bytes_per_second <= 0.0
                || self.rate_limit.subnet_burst_packets <= 0.0
                || self.rate_limit.subnet_burst_bytes <= 0.0)
        {
            bail!("subnet rate_limit values must be positive when subnet is enabled");
        }

        if self.rate_limit.subnet_ipv4_prefix > 32 {
            bail!("rate_limit.subnet_ipv4_prefix must be <= 32");
        }
        if self.rate_limit.subnet_ipv6_prefix > 128 {
            bail!("rate_limit.subnet_ipv6_prefix must be <= 128");
        }
        if self.rate_limit.max_ip_buckets == 0 {
            bail!("rate_limit.max_ip_buckets must be > 0");
        }
        if self.rate_limit.max_subnet_buckets == 0 {
            bail!("rate_limit.max_subnet_buckets must be > 0");
        }

        if !(0.0..=1.0).contains(&self.anomaly.anomaly_threshold)
            || self.anomaly.anomaly_threshold <= 0.0
        {
            bail!("anomaly.anomaly_threshold must be in range (0, 1]");
        }
        if self.anomaly.ddos_limit <= 0.0 {
            bail!("anomaly.ddos_limit must be > 0");
        }
        if self.anomaly.window_millis == 0 {
            bail!("anomaly.window_millis must be > 0");
        }
        if !(0.0..=1.0).contains(&self.anomaly.ema_alpha) || self.anomaly.ema_alpha <= 0.0 {
            bail!("anomaly.ema_alpha must be in range (0, 1]");
        }
        if self.anomaly.max_tracked_ips == 0 {
            bail!("anomaly.max_tracked_ips must be > 0");
        }
        if self.anomaly.idle_timeout_secs == 0 {
            bail!("anomaly.idle_timeout_secs must be > 0");
        }
        if self.anomaly.client_sync_threshold_ms <= 0.0 {
            bail!("anomaly.client_sync_threshold_ms must be > 0");
        }
        if !(0.0..=1.0).contains(&self.anomaly.client_sync_weight) {
            bail!("anomaly.client_sync_weight must be in range [0, 1]");
        }

        #[cfg(not(feature = "torch_anomaly"))]
        if self.anomaly.enabled && self.anomaly.model == AnomalyModel::Torch {
            bail!("anomaly.model=torch requires feature torch_anomaly");
        }
        #[cfg(feature = "torch_anomaly")]
        if self.anomaly.enabled && self.anomaly.model == AnomalyModel::Torch {
            let Some(path) = &self.anomaly.torch_model_path else {
                bail!("anomaly.torch_model_path must be set when anomaly.model=torch");
            };
            if path.trim().is_empty() {
                bail!("anomaly.torch_model_path must be non-empty when anomaly.model=torch");
            }
        }

        if !(0.0..=1.0).contains(&self.mmr.mmr_threshold) || self.mmr.mmr_threshold <= 0.0 {
            bail!("mmr.mmr_threshold must be in range (0, 1]");
        }
        if self.mmr.window_secs == 0 {
            bail!("mmr.window_secs must be > 0");
        }
        if self.mmr.idle_timeout_secs == 0 {
            bail!("mmr.idle_timeout_secs must be > 0");
        }
        if self.mmr.max_tracked_ips == 0 {
            bail!("mmr.max_tracked_ips must be > 0");
        }

        #[cfg(not(feature = "torch_anomaly"))]
        if self.mmr.enabled && self.mmr.model == MmrModel::Torch {
            bail!("mmr.model=torch requires feature torch_anomaly");
        }
        #[cfg(feature = "torch_anomaly")]
        if self.mmr.enabled && self.mmr.model == MmrModel::Torch {
            let Some(path) = &self.mmr.torch_model_path else {
                bail!("mmr.torch_model_path must be set when mmr.model=torch");
            };
            if path.trim().is_empty() {
                bail!("mmr.torch_model_path must be non-empty when mmr.model=torch");
            }
        }

        if self.cookie.enabled && self.cookie.secret.trim().is_empty() {
            bail!("cookie.secret must be non-empty when cookie is enabled");
        }
        if self.cookie.token_ttl_secs == 0 {
            bail!("cookie.token_ttl_secs must be > 0");
        }
        if !(8..=32).contains(&self.cookie.tag_bytes) {
            bail!("cookie.tag_bytes must be between 8 and 32");
        }
        if self.cookie.max_tracked_peers == 0 {
            bail!("cookie.max_tracked_peers must be > 0");
        }
        if self.cookie.challenge_packets_per_second <= 0.0
            || self.cookie.challenge_burst_packets <= 0.0
        {
            bail!("cookie challenge rate values must be positive");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_config() -> &'static str {
        r#"
[proxy]
listen_addr = "127.0.0.1:7000"
upstream_addr = "127.0.0.1:7001"
worker_count = 2
reuse_port = true
pin_workers = false
batch_size = 32
max_sessions = 4096
min_datagram_bytes = 4
max_datagram_bytes = 1400
queue_capacity = 64
telemetry_queue_capacity = 32
critical_queue_capacity = 16
critical_overflow_policy = "drop_newest"
critical_block_timeout_millis = 10
telemetry_prefixes = ["TELE:", "STAT:"]

[rate_limit]
per_ip_packets_per_second = 200.0
per_ip_burst_packets = 400.0
per_ip_bytes_per_second = 50000.0
per_ip_burst_bytes = 100000.0
global_packets_per_second = 5000.0
global_burst_packets = 10000.0
global_bytes_per_second = 10000000.0
global_burst_bytes = 20000000.0
subnet_enabled = true
subnet_ipv4_prefix = 24
subnet_ipv6_prefix = 64
subnet_packets_per_second = 1000.0
subnet_burst_packets = 2000.0
subnet_bytes_per_second = 1000000.0
subnet_burst_bytes = 2000000.0
max_ip_buckets = 4096
max_subnet_buckets = 2048
idle_timeout_secs = 60

[anomaly]
enabled = true
model = "heuristic"
anomaly_threshold = 0.8
ddos_limit = 500.0
window_millis = 200
ema_alpha = 0.35
min_packets_per_window = 8
max_tracked_ips = 4096
idle_timeout_secs = 120
client_sync_check = true
client_sync_threshold_ms = 150.0
client_sync_weight = 0.4

[packet_validation]
enabled = true
strict_mode = true
require_checksum = true
strip_checksum_header = true

[mmr]
enabled = true
model = "heuristic"
mmr_threshold = 0.8
window_secs = 60
idle_timeout_secs = 1200
max_tracked_ips = 4096

[flood_sim]
allow_non_local = false

[cookie]
enabled = true
mode = "strict"
secret = "unit-test-secret"
token_ttl_secs = 30
tag_bytes = 16
max_tracked_peers = 8192
challenge_packets_per_second = 1000.0
challenge_burst_packets = 2000.0

[metrics]
enabled = true
listen_addr = "127.0.0.1:9200"
"#
    }

    #[test]
    fn parse_valid_config() {
        let parsed = ProxyConfig::from_toml(good_config()).expect("config should parse");
        assert_eq!(parsed.proxy.worker_count, 2);
        assert_eq!(parsed.proxy.max_sessions, 4096);
        assert_eq!(parsed.proxy.telemetry_queue_capacity(), 32);
        assert_eq!(parsed.proxy.critical_queue_capacity(), 16);
        assert_eq!(parsed.proxy.downstream_telemetry_queue_capacity(), 32);
        assert_eq!(parsed.proxy.downstream_critical_queue_capacity(), 16);
        assert!(parsed.cookie.enabled);
        assert_eq!(parsed.cookie.token_ttl_secs, 30);
        assert_eq!(parsed.metrics.listen_addr.to_string(), "127.0.0.1:9200");
        assert!(parsed.rate_limit.subnet_enabled);
        assert!(parsed.anomaly.enabled);
        assert_eq!(parsed.anomaly.anomaly_threshold, 0.8);
        assert_eq!(parsed.anomaly.ddos_limit, 500.0);
        assert!(parsed.anomaly.client_sync_check);
        assert_eq!(parsed.anomaly.client_sync_threshold_ms, 150.0);
        assert_eq!(parsed.anomaly.client_sync_weight, 0.4);
        assert!(parsed.packet_validation.enabled);
        assert!(parsed.packet_validation.require_checksum);
        assert_eq!(parsed.mmr.mmr_threshold, 0.8);
        assert!(parsed.mmr.enabled);
        assert!(!parsed.flood_sim.allow_non_local);
    }

    #[test]
    fn parse_legacy_challenge_key_alias() {
        let cfg = good_config().replace("[cookie]", "[challenge]");
        let parsed = ProxyConfig::from_toml(&cfg).expect("config should parse");
        assert!(parsed.cookie.enabled);
    }

    #[test]
    fn reject_invalid_packet_bounds() {
        let cfg = good_config().replace("min_datagram_bytes = 4", "min_datagram_bytes = 2000");
        let err = ProxyConfig::from_toml(&cfg).expect_err("should fail validation");
        assert!(
            err.to_string().contains("min_datagram_bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reject_empty_cookie_secret_when_enabled() {
        let cfg = good_config().replace("secret = \"unit-test-secret\"", "secret = \"\"");
        let err = ProxyConfig::from_toml(&cfg).expect_err("should fail validation");
        assert!(
            err.to_string().contains("cookie.secret"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn missing_cookie_section_uses_defaults() {
        let cfg = r#"
[proxy]
listen_addr = "127.0.0.1:7000"
upstream_addr = "127.0.0.1:7001"

[rate_limit]
per_ip_packets_per_second = 200.0
per_ip_burst_packets = 400.0
per_ip_bytes_per_second = 50000.0
per_ip_burst_bytes = 100000.0

[metrics]
enabled = false
listen_addr = "127.0.0.1:9200"
"#;

        let parsed = ProxyConfig::from_toml(cfg).expect("config should parse");
        assert!(!parsed.cookie.enabled);
        assert_eq!(parsed.cookie.mode, CookieMode::Strict);
        assert_eq!(parsed.cookie.secret, "replace-me");
        assert_eq!(parsed.cookie.token_ttl_secs, 20);
        assert_eq!(parsed.cookie.tag_bytes, 16);
        assert_eq!(parsed.cookie.max_tracked_peers, 65_536);
        assert_eq!(parsed.cookie.challenge_packets_per_second, 5_000.0);
        assert_eq!(parsed.cookie.challenge_burst_packets, 10_000.0);
        assert!(!parsed.anomaly.enabled);
        assert_eq!(parsed.anomaly.anomaly_threshold, 0.8);
        assert_eq!(parsed.anomaly.ddos_limit, 500.0);
        assert!(!parsed.flood_sim.allow_non_local);
    }

    #[test]
    fn parse_ddos_limit_alias() {
        let cfg = r#"
[proxy]
listen_addr = "127.0.0.1:7000"
upstream_addr = "127.0.0.1:7001"

[rate_limit]
ddos_limit = 500.0
per_ip_burst_packets = 1000.0
per_ip_bytes_per_second = 500000.0
per_ip_burst_bytes = 1000000.0

[metrics]
enabled = false
listen_addr = "127.0.0.1:9200"
"#;
        let parsed = ProxyConfig::from_toml(cfg).expect("config should parse");
        assert_eq!(parsed.rate_limit.per_ip_packets_per_second, 500.0);
    }

    #[test]
    fn reject_invalid_anomaly_threshold() {
        let cfg = good_config().replace("anomaly_threshold = 0.8", "anomaly_threshold = 1.5");
        let err = ProxyConfig::from_toml(&cfg).expect_err("should fail validation");
        assert!(
            err.to_string().contains("anomaly.anomaly_threshold"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reject_zero_anomaly_window() {
        let cfg = good_config().replace("window_millis = 200", "window_millis = 0");
        let err = ProxyConfig::from_toml(&cfg).expect_err("should fail validation");
        assert!(
            err.to_string().contains("anomaly.window_millis"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn missing_anomaly_model_uses_default() {
        let cfg = good_config().replace("model = \"heuristic\"\n", "");
        let parsed = ProxyConfig::from_toml(&cfg).expect("config should parse");
        assert_eq!(parsed.anomaly.model, AnomalyModel::Heuristic);
    }

    #[test]
    fn reject_invalid_mmr_threshold() {
        let cfg = good_config().replace("mmr_threshold = 0.8", "mmr_threshold = 1.5");
        let err = ProxyConfig::from_toml(&cfg).expect_err("should fail validation");
        assert!(
            err.to_string().contains("mmr.mmr_threshold"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(feature = "torch_anomaly"))]
    #[test]
    fn reject_torch_anomaly_without_feature() {
        let cfg = good_config().replace("model = \"heuristic\"", "model = \"torch\"");
        let err = ProxyConfig::from_toml(&cfg).expect_err("torch model should fail");
        assert!(
            err.to_string().contains("torch_anomaly"),
            "unexpected error: {err}"
        );
    }
}
