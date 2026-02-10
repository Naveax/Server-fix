#![no_main]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use libfuzzer_sys::fuzz_target;
use nx_proxy::challenge::ChallengeGate;
use nx_proxy::config::{CookieMode, CookieSection, RateLimitSection};
use nx_proxy::packet::{decode_client_frame, validate_packet_size, PacketLimits};
use nx_proxy::rate_limit::{MultiScopeRateLimiter, RateLimiterConfig};

fuzz_target!(|data: &[u8]| {
    let tag_len = if data.is_empty() {
        16
    } else {
        (data[0] as usize % 24) + 8
    };

    let _ = decode_client_frame(data, tag_len);
    let _ = validate_packet_size(
        data,
        PacketLimits {
            min_packet_size: 1,
            max_packet_size: 1400,
        },
    );

    let rate_cfg = RateLimitSection {
        per_ip_packets_per_second: 500.0,
        per_ip_burst_packets: 500.0,
        per_ip_bytes_per_second: 5_000_000.0,
        per_ip_burst_bytes: 5_000_000.0,
        global_packets_per_second: 50_000.0,
        global_burst_packets: 50_000.0,
        global_bytes_per_second: 50_000_000.0,
        global_burst_bytes: 50_000_000.0,
        subnet_enabled: true,
        subnet_ipv4_prefix: 24,
        subnet_ipv6_prefix: 64,
        subnet_packets_per_second: 5_000.0,
        subnet_burst_packets: 5_000.0,
        subnet_bytes_per_second: 5_000_000.0,
        subnet_burst_bytes: 5_000_000.0,
        max_ip_buckets: 512,
        max_subnet_buckets: 512,
        idle_timeout_secs: 30,
    };
    let mut limiter = MultiScopeRateLimiter::new(RateLimiterConfig::from(&rate_cfg));

    let ip = IpAddr::V4(Ipv4Addr::new(
        data.get(1).copied().unwrap_or(127),
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
        data.get(4).copied().unwrap_or(1),
    ));
    let _ = limiter.allow(ip, data.len().max(1));

    let cookie_cfg = CookieSection {
        enabled: true,
        mode: if data.get(5).copied().unwrap_or(0) % 2 == 0 {
            CookieMode::Strict
        } else {
            CookieMode::Compat
        },
        secret: "fuzz-secret".to_string(),
        token_ttl_secs: 20,
        tag_bytes: tag_len,
        max_tracked_peers: 1024,
        challenge_packets_per_second: 1000.0,
        challenge_burst_packets: 1000.0,
    };
    let mut gate = ChallengeGate::new(&cookie_cfg);
    let src = SocketAddr::new(ip, 20000 + u16::from(data.get(6).copied().unwrap_or(0)));
    let _ = gate.evaluate(src, data, 1_700_000_000);
});
