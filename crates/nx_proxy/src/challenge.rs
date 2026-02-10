use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use crate::config::{CookieMode, CookieSection};
use crate::packet::{
    cookie_header_len, decode_client_frame, ClientFrame, COOKIE_KIND_CHALLENGE,
    COOKIE_KIND_RESPONSE, COOKIE_MAGIC, COOKIE_VERSION,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct ChallengeGate {
    enabled: bool,
    mode: CookieMode,
    secret: Vec<u8>,
    token_ttl_secs: u64,
    tag_bytes: usize,
    seen_peers: SeenPeers,
    challenge_rate_limiter: PacketBucket,
    salt: [u8; 8],
}

pub enum GateDecision<'a> {
    Forward(&'a [u8]),
    ForwardVerified(&'a [u8]),
    Challenge(Vec<u8>),
    Drop(&'static str),
}

impl ChallengeGate {
    pub fn new(section: &CookieSection) -> Self {
        let mut salt = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt);
        Self {
            enabled: section.enabled,
            mode: section.mode,
            secret: section.secret.as_bytes().to_vec(),
            token_ttl_secs: section.token_ttl_secs.max(1),
            tag_bytes: section.tag_bytes.clamp(8, 32),
            seen_peers: SeenPeers::new(section.max_tracked_peers.max(1)),
            challenge_rate_limiter: PacketBucket::new(
                section.challenge_packets_per_second,
                section.challenge_burst_packets,
            ),
            salt,
        }
    }

    pub fn evaluate<'a>(
        &mut self,
        src: SocketAddr,
        packet: &'a [u8],
        now_secs: u64,
    ) -> GateDecision<'a> {
        if !self.enabled {
            return GateDecision::Forward(packet);
        }

        let now = Instant::now();
        self.seen_peers.gc_stale(now_secs, self.token_ttl_secs);
        let known_peer = self.seen_peers.is_known(src, now_secs, self.token_ttl_secs);

        match decode_client_frame(packet, self.tag_bytes) {
            ClientFrame::RawPayload(payload) => {
                if known_peer {
                    self.seen_peers.mark_seen(src, now_secs);
                    return GateDecision::Forward(payload);
                }

                match self.mode {
                    CookieMode::Compat => {
                        self.seen_peers.mark_seen(src, now_secs);
                        GateDecision::Forward(payload)
                    }
                    CookieMode::Strict => {
                        if self.challenge_rate_limiter.allow(now) {
                            GateDecision::Challenge(self.build_challenge_packet(src, now_secs))
                        } else {
                            GateDecision::Drop("cookie_challenge_rate_limited")
                        }
                    }
                }
            }
            ClientFrame::CookieChallenge => {
                if self.challenge_rate_limiter.allow(now) {
                    GateDecision::Challenge(self.build_challenge_packet(src, now_secs))
                } else {
                    GateDecision::Drop("cookie_challenge_rate_limited")
                }
            }
            ClientFrame::CookieResponse(frame) => {
                if frame.payload.is_empty() {
                    return GateDecision::Drop("cookie_empty_payload");
                }

                if !self.verify(
                    src,
                    frame.issued_at_secs as u64,
                    frame.nonce,
                    frame.mac,
                    now_secs,
                ) {
                    return GateDecision::Drop("cookie_invalid");
                }

                self.seen_peers.mark_seen(src, now_secs);
                GateDecision::ForwardVerified(frame.payload)
            }
            ClientFrame::Malformed(_) => GateDecision::Drop("cookie_malformed"),
        }
    }

    pub fn build_challenge_packet(&self, src: SocketAddr, now_secs: u64) -> Vec<u8> {
        let issued_at_secs = now_secs as u32;
        let nonce = random_nonce();
        let tag = compute_tag(&self.secret, src, issued_at_secs, nonce, self.salt);
        let header_len = cookie_header_len(self.tag_bytes);

        let mut out = Vec::with_capacity(header_len);
        out.extend_from_slice(&COOKIE_MAGIC);
        out.push(COOKIE_VERSION);
        out.push(COOKIE_KIND_CHALLENGE);
        out.extend_from_slice(&issued_at_secs.to_be_bytes());
        out.extend_from_slice(&nonce.to_be_bytes());
        out.extend_from_slice(&tag[..self.tag_bytes]);
        out
    }

    fn verify(
        &self,
        src: SocketAddr,
        issued_at_secs: u64,
        nonce: u64,
        mac: &[u8],
        now_secs: u64,
    ) -> bool {
        if issued_at_secs > now_secs + 1 {
            return false;
        }

        if now_secs.saturating_sub(issued_at_secs) > self.token_ttl_secs {
            return false;
        }

        if mac.len() != self.tag_bytes {
            return false;
        }

        let tag = compute_tag(&self.secret, src, issued_at_secs as u32, nonce, self.salt);
        constant_time_eq(mac, &tag[..self.tag_bytes])
    }
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn build_response_packet_from_challenge(
    challenge_packet: &[u8],
    payload: &[u8],
    tag_bytes: usize,
) -> Option<Vec<u8>> {
    let header_len = cookie_header_len(tag_bytes);
    if challenge_packet.len() != header_len {
        return None;
    }

    let mut response = Vec::with_capacity(header_len + payload.len());
    response.extend_from_slice(challenge_packet);
    if response.get(5).copied()? != COOKIE_KIND_CHALLENGE {
        return None;
    }
    response[5] = COOKIE_KIND_RESPONSE;
    response.extend_from_slice(payload);
    Some(response)
}

#[derive(Debug, Clone)]
struct PacketBucket {
    packets_per_second: f64,
    burst_packets: f64,
    tokens: f64,
    last_refill: Instant,
}

impl PacketBucket {
    fn new(packets_per_second: f64, burst_packets: f64) -> Self {
        let now = Instant::now();
        Self {
            packets_per_second: packets_per_second.max(1.0),
            burst_packets: burst_packets.max(1.0),
            tokens: burst_packets.max(1.0),
            last_refill: now,
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed > f64::EPSILON {
            self.tokens = (self.tokens + elapsed * self.packets_per_second).min(self.burst_packets);
            self.last_refill = now;
        }

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
struct SeenPeers {
    peers: HashMap<SocketAddr, u64>,
    lru: VecDeque<SocketAddr>,
    capacity: usize,
}

impl SeenPeers {
    fn new(capacity: usize) -> Self {
        Self {
            peers: HashMap::new(),
            lru: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    fn mark_seen(&mut self, peer: SocketAddr, now_secs: u64) {
        if !self.peers.contains_key(&peer) && self.peers.len() >= self.capacity {
            self.evict_one();
        }
        self.peers.insert(peer, now_secs);
        self.lru.push_back(peer);
        self.compact_lru_if_needed();
    }

    fn gc_stale(&mut self, now_secs: u64, ttl_secs: u64) {
        let before = self.peers.len();
        self.peers
            .retain(|_, last_seen| now_secs.saturating_sub(*last_seen) <= ttl_secs);
        if self.peers.len() < before {
            self.lru.retain(|peer| self.peers.contains_key(peer));
        }
        self.compact_lru_if_needed();
    }

    fn is_known(&mut self, peer: SocketAddr, now_secs: u64, ttl_secs: u64) -> bool {
        let Some(last_seen) = self.peers.get(&peer).copied() else {
            return false;
        };
        if now_secs.saturating_sub(last_seen) > ttl_secs {
            self.peers.remove(&peer);
            return false;
        }
        true
    }

    fn evict_one(&mut self) {
        while let Some(candidate) = self.lru.pop_front() {
            if self.peers.remove(&candidate).is_some() {
                break;
            }
        }
    }

    fn compact_lru_if_needed(&mut self) {
        let cap = self.capacity.saturating_mul(8).max(128);
        if self.lru.len() <= cap {
            return;
        }

        let mut seen = HashSet::with_capacity(self.peers.len());
        let mut compacted = VecDeque::with_capacity(self.peers.len());
        while let Some(peer) = self.lru.pop_back() {
            if self.peers.contains_key(&peer) && seen.insert(peer) {
                compacted.push_front(peer);
            }
        }
        self.lru = compacted;
    }

    #[cfg(test)]
    fn lru_len(&self) -> usize {
        self.lru.len()
    }
}

fn random_nonce() -> u64 {
    let mut rng = rand::thread_rng();
    rng.next_u64()
}

fn compute_tag(
    secret: &[u8],
    src: SocketAddr,
    issued_at_secs: u32,
    nonce: u64,
    salt: [u8; 8],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key should initialize");
    update_mac_input(&mut mac, src, issued_at_secs, nonce, salt);

    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn update_mac_input(
    mac: &mut HmacSha256,
    src: SocketAddr,
    issued_at_secs: u32,
    nonce: u64,
    salt: [u8; 8],
) {
    mac.update(&[COOKIE_VERSION]);
    mac.update(&salt);

    match src.ip() {
        IpAddr::V4(ipv4) => {
            mac.update(&[4]);
            mac.update(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            mac.update(&[6]);
            mac.update(&ipv6.octets());
        }
    }

    mac.update(&src.port().to_be_bytes());
    mac.update(&issued_at_secs.to_be_bytes());
    mac.update(&nonce.to_be_bytes());
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (lhs, rhs) in a.iter().zip(b.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CookieMode, CookieSection};

    fn strict_cookie() -> CookieSection {
        CookieSection {
            enabled: true,
            mode: CookieMode::Strict,
            secret: "test-secret".into(),
            token_ttl_secs: 30,
            tag_bytes: 16,
            max_tracked_peers: 64,
            challenge_packets_per_second: 10.0,
            challenge_burst_packets: 10.0,
        }
    }

    #[test]
    fn challenge_round_trip_verifies() {
        let mut gate = ChallengeGate::new(&strict_cookie());
        let src: SocketAddr = "127.0.0.1:12345".parse().expect("valid addr");
        let now = 100;

        let challenge = gate.build_challenge_packet(src, now);
        let payload = b"hello";
        let response =
            build_response_packet_from_challenge(&challenge, payload, 16).expect("response packet");

        let decision = gate.evaluate(src, &response, now + 1);
        match decision {
            GateDecision::ForwardVerified(forwarded) => assert_eq!(forwarded, payload),
            _ => panic!("expected packet to pass challenge gate"),
        }
    }

    #[test]
    fn strict_mode_challenges_unknown_payload() {
        let mut gate = ChallengeGate::new(&strict_cookie());
        let src: SocketAddr = "127.0.0.1:12345".parse().expect("valid addr");

        let decision = gate.evaluate(src, b"payload", 100);
        assert!(matches!(decision, GateDecision::Challenge(_)));
    }

    #[test]
    fn compat_mode_forwards_unknown_payload() {
        let mut cfg = strict_cookie();
        cfg.mode = CookieMode::Compat;
        let mut gate = ChallengeGate::new(&cfg);
        let src: SocketAddr = "127.0.0.1:12345".parse().expect("valid addr");

        let decision = gate.evaluate(src, b"payload", 100);
        assert!(matches!(decision, GateDecision::Forward(b"payload")));
    }

    #[test]
    fn expired_cookie_is_rejected() {
        let mut section = strict_cookie();
        section.token_ttl_secs = 2;
        let mut gate = ChallengeGate::new(&section);
        let src: SocketAddr = "127.0.0.1:12345".parse().expect("valid addr");

        let challenge = gate.build_challenge_packet(src, 10);
        let response = build_response_packet_from_challenge(&challenge, b"payload", 16)
            .expect("response packet");

        let decision = gate.evaluate(src, &response, 20);
        match decision {
            GateDecision::Drop(reason) => assert_eq!(reason, "cookie_invalid"),
            _ => panic!("expected expired challenge to be dropped"),
        }
    }

    #[test]
    fn seen_peers_lru_is_compacted_and_bounded() {
        let mut peers = SeenPeers::new(2);
        let peer: SocketAddr = "127.0.0.1:12345".parse().expect("valid addr");

        for now in 0..5000 {
            peers.mark_seen(peer, now);
        }

        let cap = peers.capacity.saturating_mul(8).max(128);
        assert!(
            peers.lru_len() <= cap,
            "lru len {} exceeded cap {}",
            peers.lru_len(),
            cap
        );
    }

    #[test]
    fn seen_peers_gc_prunes_stale_lru_entries() {
        let mut peers = SeenPeers::new(4);
        let stale_peer: SocketAddr = "127.0.0.1:11111".parse().expect("valid addr");
        let live_peer: SocketAddr = "127.0.0.1:22222".parse().expect("valid addr");
        peers.mark_seen(stale_peer, 10);
        peers.mark_seen(live_peer, 100);

        peers.gc_stale(120, 30);
        assert!(!peers.peers.contains_key(&stale_peer));
        assert!(peers.peers.contains_key(&live_peer));
        assert!(peers.lru.iter().all(|p| peers.peers.contains_key(p)));
    }

    #[test]
    fn seen_peers_invariants_hold_under_time_advanced_churn() {
        let mut peers = SeenPeers::new(32);
        let mut now_secs = 1_000u64;
        let ttl_secs = 30u64;
        let mut seed = 0x2468_ACE0u32;

        for iter in 0..15_000usize {
            if iter % 40 == 0 {
                now_secs += 1;
                peers.gc_stale(now_secs, ttl_secs);
            }

            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let peer = SocketAddr::from((
                [
                    10,
                    ((seed >> 16) & 0xFF) as u8,
                    ((seed >> 8) & 0xFF) as u8,
                    (seed & 0xFF) as u8,
                ],
                10_000 + ((seed >> 24) as u16),
            ));

            peers.mark_seen(peer, now_secs);
            let cap = peers.capacity.saturating_mul(8).max(128);
            assert!(
                peers.lru_len() <= cap,
                "lru len {} exceeded cap {}",
                peers.lru_len(),
                cap
            );
            assert!(peers.lru.iter().all(|p| peers.peers.contains_key(p)));
        }
    }
}
