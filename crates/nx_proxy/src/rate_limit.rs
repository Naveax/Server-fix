use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::config::RateLimitSection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitScope {
    Global,
    Ip,
    Subnet,
}

impl RateLimitScope {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Ip => "ip",
            Self::Subnet => "subnet",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BucketConfig {
    pub packets_per_second: f64,
    pub burst_packets: f64,
    pub bytes_per_second: f64,
    pub burst_bytes: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct SubnetConfig {
    pub bucket: BucketConfig,
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
}

#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    pub global: BucketConfig,
    pub per_ip: BucketConfig,
    pub subnet: Option<SubnetConfig>,
    pub idle_timeout: Duration,
    pub max_ip_buckets: usize,
    pub max_subnet_buckets: usize,
}

impl From<&RateLimitSection> for RateLimiterConfig {
    fn from(value: &RateLimitSection) -> Self {
        let subnet = if value.subnet_enabled {
            Some(SubnetConfig {
                bucket: BucketConfig {
                    packets_per_second: value.subnet_packets_per_second,
                    burst_packets: value.subnet_burst_packets,
                    bytes_per_second: value.subnet_bytes_per_second,
                    burst_bytes: value.subnet_burst_bytes,
                },
                ipv4_prefix: value.subnet_ipv4_prefix,
                ipv6_prefix: value.subnet_ipv6_prefix,
            })
        } else {
            None
        };

        Self {
            global: BucketConfig {
                packets_per_second: value.global_packets_per_second,
                burst_packets: value.global_burst_packets,
                bytes_per_second: value.global_bytes_per_second,
                burst_bytes: value.global_burst_bytes,
            },
            per_ip: BucketConfig {
                packets_per_second: value.per_ip_packets_per_second,
                burst_packets: value.per_ip_burst_packets,
                bytes_per_second: value.per_ip_bytes_per_second,
                burst_bytes: value.per_ip_burst_bytes,
            },
            subnet,
            idle_timeout: Duration::from_secs(value.idle_timeout_secs.max(1)),
            max_ip_buckets: value.max_ip_buckets.max(1),
            max_subnet_buckets: value.max_subnet_buckets.max(1),
        }
    }
}

#[derive(Debug)]
struct TokenBucket {
    packet_tokens: f64,
    byte_tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(now: Instant, cfg: BucketConfig) -> Self {
        Self {
            packet_tokens: cfg.burst_packets,
            byte_tokens: cfg.burst_bytes,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant, cfg: BucketConfig) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed <= f64::EPSILON {
            return;
        }

        self.packet_tokens =
            (self.packet_tokens + elapsed * cfg.packets_per_second).min(cfg.burst_packets);
        self.byte_tokens = (self.byte_tokens + elapsed * cfg.bytes_per_second).min(cfg.burst_bytes);
        self.last_refill = now;
    }

    fn try_consume(&mut self, now: Instant, cfg: BucketConfig, packet_len: usize) -> bool {
        self.refill(now, cfg);
        let needed_packets = 1.0;
        let needed_bytes = packet_len as f64;
        if self.packet_tokens >= needed_packets && self.byte_tokens >= needed_bytes {
            self.packet_tokens -= needed_packets;
            self.byte_tokens -= needed_bytes;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
struct BucketEntry {
    bucket: TokenBucket,
    last_seen: Instant,
}

#[derive(Debug)]
struct BoundedBucketStore<K>
where
    K: Eq + Hash + Clone,
{
    entries: HashMap<K, BucketEntry>,
    lru: VecDeque<K>,
    capacity: usize,
    idle_timeout: Duration,
}

impl<K> BoundedBucketStore<K>
where
    K: Eq + Hash + Clone,
{
    fn new(capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            lru: VecDeque::new(),
            capacity: capacity.max(1),
            idle_timeout,
        }
    }

    fn allow(&mut self, key: K, now: Instant, cfg: BucketConfig, packet_len: usize) -> bool {
        self.gc_idle(now);

        if !self.entries.contains_key(&key) {
            self.evict_one_if_full();
            self.entries.insert(
                key.clone(),
                BucketEntry {
                    bucket: TokenBucket::new(now, cfg),
                    last_seen: now,
                },
            );
        }

        self.lru.push_back(key.clone());
        let Some(entry) = self.entries.get_mut(&key) else {
            return false;
        };
        entry.last_seen = now;
        entry.bucket.try_consume(now, cfg, packet_len)
    }

    fn evict_one_if_full(&mut self) {
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
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| now.saturating_duration_since(entry.last_seen) <= self.idle_timeout);
        if self.entries.len() < before {
            self.lru.retain(|k| self.entries.contains_key(k));
        }
        self.compact_lru_if_needed();
    }

    fn compact_lru_if_needed(&mut self) {
        let cap = self.capacity.saturating_mul(8).max(128);
        if self.lru.len() <= cap {
            return;
        }

        let mut seen = HashSet::with_capacity(self.entries.len());
        let mut compacted = VecDeque::with_capacity(self.entries.len());
        while let Some(key) = self.lru.pop_back() {
            if self.entries.contains_key(&key) && seen.insert(key.clone()) {
                compacted.push_front(key);
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

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct SubnetKey {
    family: u8,
    prefix: u8,
    bytes: [u8; 16],
}

impl SubnetKey {
    fn from_ip(ip: IpAddr, ipv4_prefix: u8, ipv6_prefix: u8) -> Self {
        match ip {
            IpAddr::V4(addr) => {
                let mut bytes = [0u8; 16];
                bytes[..4].copy_from_slice(&mask_v4(addr, ipv4_prefix).octets());
                Self {
                    family: 4,
                    prefix: ipv4_prefix,
                    bytes,
                }
            }
            IpAddr::V6(addr) => Self {
                family: 6,
                prefix: ipv6_prefix,
                bytes: mask_v6(addr, ipv6_prefix).octets(),
            },
        }
    }
}

fn mask_v4(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let prefix = prefix.min(32);
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask: u32 = (!0u32) << (32 - prefix);
    let value = u32::from(addr) & mask;
    Ipv4Addr::from(value)
}

fn mask_v6(addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let prefix = prefix.min(128);
    if prefix == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let value = u128::from_be_bytes(addr.octets());
    let mask: u128 = (!0u128) << (128 - prefix);
    Ipv6Addr::from(value & mask)
}

#[derive(Debug)]
pub struct MultiScopeRateLimiter {
    cfg: RateLimiterConfig,
    global_bucket: TokenBucket,
    ip_buckets: BoundedBucketStore<IpAddr>,
    subnet_buckets: Option<BoundedBucketStore<SubnetKey>>,
}

impl MultiScopeRateLimiter {
    pub fn new(cfg: RateLimiterConfig) -> Self {
        let now = Instant::now();
        let subnet_buckets = cfg
            .subnet
            .map(|_| BoundedBucketStore::new(cfg.max_subnet_buckets, cfg.idle_timeout));
        Self {
            global_bucket: TokenBucket::new(now, cfg.global),
            ip_buckets: BoundedBucketStore::new(cfg.max_ip_buckets, cfg.idle_timeout),
            subnet_buckets,
            cfg,
        }
    }

    pub fn allow(&mut self, source_ip: IpAddr, packet_len: usize) -> Result<(), RateLimitScope> {
        self.allow_at(source_ip, packet_len, Instant::now())
    }

    pub(crate) fn allow_at(
        &mut self,
        source_ip: IpAddr,
        packet_len: usize,
        now: Instant,
    ) -> Result<(), RateLimitScope> {
        if !self
            .global_bucket
            .try_consume(now, self.cfg.global, packet_len)
        {
            return Err(RateLimitScope::Global);
        }

        if !self
            .ip_buckets
            .allow(source_ip, now, self.cfg.per_ip, packet_len)
        {
            return Err(RateLimitScope::Ip);
        }

        if let (Some(subnet_cfg), Some(subnet_buckets)) =
            (self.cfg.subnet, self.subnet_buckets.as_mut())
        {
            let subnet_key =
                SubnetKey::from_ip(source_ip, subnet_cfg.ipv4_prefix, subnet_cfg.ipv6_prefix);
            if !subnet_buckets.allow(subnet_key, now, subnet_cfg.bucket, packet_len) {
                return Err(RateLimitScope::Subnet);
            }
        }

        Ok(())
    }

    #[cfg(test)]
    fn ip_bucket_len(&self) -> usize {
        self.ip_buckets.len()
    }

    #[cfg(test)]
    fn ip_lru_len(&self) -> usize {
        self.ip_buckets.lru_len()
    }
}

#[cfg(test)]
mod tests {
    use std::hash::Hash;
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn assert_store_invariants<K>(store: &BoundedBucketStore<K>)
    where
        K: Eq + Hash + Clone,
    {
        let cap = store.capacity.saturating_mul(8).max(128);
        assert!(
            store.lru.len() <= cap,
            "lru len {} exceeded cap {}",
            store.lru.len(),
            cap
        );
        assert!(
            store.lru.iter().all(|key| store.entries.contains_key(key)),
            "lru contains keys that are not present in map"
        );
    }

    fn cfg() -> RateLimiterConfig {
        RateLimiterConfig {
            global: BucketConfig {
                packets_per_second: 100.0,
                burst_packets: 100.0,
                bytes_per_second: 1000.0,
                burst_bytes: 1000.0,
            },
            per_ip: BucketConfig {
                packets_per_second: 2.0,
                burst_packets: 2.0,
                bytes_per_second: 20.0,
                burst_bytes: 20.0,
            },
            subnet: Some(SubnetConfig {
                bucket: BucketConfig {
                    packets_per_second: 3.0,
                    burst_packets: 3.0,
                    bytes_per_second: 30.0,
                    burst_bytes: 30.0,
                },
                ipv4_prefix: 24,
                ipv6_prefix: 64,
            }),
            idle_timeout: Duration::from_secs(30),
            max_ip_buckets: 2,
            max_subnet_buckets: 2,
        }
    }

    #[test]
    fn global_budget_is_enforced() {
        let mut cfg = cfg();
        cfg.global = BucketConfig {
            packets_per_second: 2.0,
            burst_packets: 2.0,
            bytes_per_second: 20.0,
            burst_bytes: 20.0,
        };
        cfg.per_ip = BucketConfig {
            packets_per_second: 100.0,
            burst_packets: 100.0,
            bytes_per_second: 1000.0,
            burst_bytes: 1000.0,
        };
        cfg.subnet = None;
        let mut limiter = MultiScopeRateLimiter::new(cfg);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let base = Instant::now();

        assert!(limiter.allow_at(ip, 10, base).is_ok());
        assert!(limiter.allow_at(ip, 10, base).is_ok());
        assert_eq!(limiter.allow_at(ip, 10, base), Err(RateLimitScope::Global));
    }

    #[test]
    fn ip_budget_is_isolated_per_address() {
        let mut limiter = MultiScopeRateLimiter::new(cfg());
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let base = Instant::now();

        assert!(limiter.allow_at(ip1, 1, base).is_ok());
        assert!(limiter.allow_at(ip1, 1, base).is_ok());
        assert!(matches!(
            limiter.allow_at(ip1, 1, base),
            Err(RateLimitScope::Ip | RateLimitScope::Global)
        ));
        assert!(limiter.allow_at(ip2, 1, base).is_ok());
    }

    #[test]
    fn subnet_budget_is_enforced() {
        let mut cfg = cfg();
        cfg.global = BucketConfig {
            packets_per_second: 100.0,
            burst_packets: 100.0,
            bytes_per_second: 1000.0,
            burst_bytes: 1000.0,
        };
        cfg.per_ip = cfg.global;
        cfg.subnet = Some(SubnetConfig {
            bucket: BucketConfig {
                packets_per_second: 1.0,
                burst_packets: 1.0,
                bytes_per_second: 1000.0,
                burst_bytes: 1000.0,
            },
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        });
        let mut limiter = MultiScopeRateLimiter::new(cfg);
        let base = Instant::now();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 3));

        assert!(limiter.allow_at(ip1, 100, base).is_ok());
        assert_eq!(
            limiter.allow_at(ip2, 100, base),
            Err(RateLimitScope::Subnet)
        );
    }

    #[test]
    fn ip_buckets_are_bounded() {
        let mut limiter = MultiScopeRateLimiter::new(cfg());
        let base = Instant::now();

        assert!(limiter
            .allow_at(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1, base)
            .is_ok());
        assert!(limiter
            .allow_at(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1, base)
            .is_ok());
        assert!(limiter
            .allow_at(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 1, base)
            .is_ok());
        assert!(limiter.ip_bucket_len() <= 2);
    }

    #[test]
    fn ip_lru_is_compacted_and_bounded() {
        let mut cfg = cfg();
        cfg.global = BucketConfig {
            packets_per_second: 1_000_000.0,
            burst_packets: 1_000_000.0,
            bytes_per_second: 1_000_000_000.0,
            burst_bytes: 1_000_000_000.0,
        };
        cfg.per_ip = cfg.global;
        cfg.max_ip_buckets = 2;
        cfg.subnet = None;
        let mut limiter = MultiScopeRateLimiter::new(cfg);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
        let now = Instant::now();

        for _ in 0..5000 {
            let _ = limiter.allow_at(ip, 1, now);
        }

        let cap = limiter.cfg.max_ip_buckets.saturating_mul(8).max(128);
        assert!(
            limiter.ip_lru_len() <= cap,
            "lru len {} exceeded cap {}",
            limiter.ip_lru_len(),
            cap
        );
    }

    #[test]
    fn ip_lru_prunes_dead_keys_during_gc() {
        let mut store = BoundedBucketStore::new(4, Duration::from_secs(1));
        let bucket_cfg = BucketConfig {
            packets_per_second: 10_000.0,
            burst_packets: 10_000.0,
            bytes_per_second: 10_000_000.0,
            burst_bytes: 10_000_000.0,
        };
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let t0 = Instant::now();

        assert!(store.allow(ip1, t0, bucket_cfg, 64));
        assert!(store.allow(ip2, t0, bucket_cfg, 64));
        assert!(store.allow(ip2, t0 + Duration::from_secs(5), bucket_cfg, 64));

        assert!(!store.entries.contains_key(&ip1));
        assert!(store.entries.contains_key(&ip2));
        assert!(store.lru.iter().all(|k| store.entries.contains_key(k)));
    }

    #[test]
    fn ip_lru_invariants_hold_under_time_advanced_churn() {
        let mut cfg = cfg();
        cfg.global = BucketConfig {
            packets_per_second: 1_000_000.0,
            burst_packets: 1_000_000.0,
            bytes_per_second: 1_000_000_000.0,
            burst_bytes: 1_000_000_000.0,
        };
        cfg.per_ip = cfg.global;
        cfg.subnet = None;
        cfg.max_ip_buckets = 32;
        cfg.idle_timeout = Duration::from_millis(200);

        let mut limiter = MultiScopeRateLimiter::new(cfg);
        let mut now = Instant::now();
        let mut seed = 0x1357_9BDFu32;

        for iter in 0..15_000usize {
            if iter % 50 == 0 {
                now += Duration::from_millis(10);
            }

            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let ip = IpAddr::V4(Ipv4Addr::new(
                10,
                ((seed >> 16) & 0xFF) as u8,
                ((seed >> 8) & 0xFF) as u8,
                (seed & 0xFF) as u8,
            ));

            let _ = limiter.allow_at(ip, 64, now);
            assert_store_invariants(&limiter.ip_buckets);
        }
    }
}
