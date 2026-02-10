#![no_main]

use std::net::SocketAddr;

use libfuzzer_sys::fuzz_target;
use nx_proxy::challenge::{ChallengeGate, GateDecision};
use nx_proxy::config::{CookieMode, CookieSection};
use nx_proxy::packet::{validate_packet_size, PacketLimits};

fuzz_target!(|data: &[u8]| {
    let limits = PacketLimits {
        min_packet_size: 1,
        max_packet_size: 1400,
    };
    let _ = validate_packet_size(data, limits);

    let mut gate = ChallengeGate::new(&CookieSection {
        enabled: true,
        mode: CookieMode::Strict,
        secret: "fuzz-secret".to_string(),
        token_ttl_secs: 20,
        tag_bytes: 16,
        max_tracked_peers: 1024,
        challenge_packets_per_second: 1000.0,
        challenge_burst_packets: 1000.0,
    });

    let src = SocketAddr::from(([127, 0, 0, 1], 35000));
    match gate.evaluate(src, data, 1_700_000_000) {
        GateDecision::Forward(payload) | GateDecision::ForwardVerified(payload) => {
            let _ = validate_packet_size(payload, limits);
        }
        GateDecision::Challenge(challenge) => {
            let _ = challenge.len();
        }
        GateDecision::Drop(_) => {}
    }
});
