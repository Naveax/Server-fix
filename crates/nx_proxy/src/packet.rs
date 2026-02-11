pub const COOKIE_MAGIC: [u8; 4] = *b"NXCG";
pub const COOKIE_VERSION: u8 = 1;
pub const COOKIE_KIND_CHALLENGE: u8 = 1;
pub const COOKIE_KIND_RESPONSE: u8 = 2;
pub const COOKIE_MIN_TAG_LEN: usize = 8;
pub const COOKIE_MAX_TAG_LEN: usize = 32;
pub const COOKIE_HEADER_BASE_LEN: usize = 4 + 1 + 1 + 4 + 8;
pub const CHECKSUM_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct PacketLimits {
    pub min_packet_size: usize,
    pub max_packet_size: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PacketValidationPolicy {
    pub enabled: bool,
    pub strict_mode: bool,
    pub require_checksum: bool,
    pub strip_checksum_header: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDecodeError {
    TooShort,
    InvalidVersion,
    UnknownKind,
}

#[derive(Debug, Clone, Copy)]
pub struct CookieEnvelope<'a> {
    pub issued_at_secs: u32,
    pub nonce: u64,
    pub mac: &'a [u8],
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub enum ClientFrame<'a> {
    RawPayload(&'a [u8]),
    CookieChallenge,
    CookieResponse(CookieEnvelope<'a>),
    Malformed(FrameDecodeError),
}

pub fn cookie_header_len(tag_len: usize) -> usize {
    COOKIE_HEADER_BASE_LEN + tag_len
}

pub fn validate_packet_size(packet: &[u8], limits: PacketLimits) -> Result<(), &'static str> {
    if packet.len() < limits.min_packet_size {
        return Err("packet_too_small");
    }
    if packet.len() > limits.max_packet_size {
        return Err("packet_too_large");
    }
    Ok(())
}

pub fn validate_packet(
    packet: &[u8],
    limits: PacketLimits,
    policy: PacketValidationPolicy,
) -> Result<&[u8], &'static str> {
    if !policy.enabled {
        validate_packet_size(packet, limits)?;
        return Ok(packet);
    }

    let payload = if policy.require_checksum {
        if packet.len() < CHECKSUM_HEADER_LEN {
            return Err("checksum_header_too_short");
        }
        let declared_len =
            u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
        let checksum = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let payload = &packet[CHECKSUM_HEADER_LEN..];
        if declared_len != payload.len() {
            return Err("checksum_length_mismatch");
        }
        if adler32(payload) != checksum {
            return Err("checksum_mismatch");
        }
        if policy.strip_checksum_header {
            payload
        } else {
            packet
        }
    } else {
        packet
    };

    validate_packet_size(payload, limits)?;
    if policy.strict_mode && payload.iter().all(|byte| *byte == 0) {
        return Err("packet_all_zeros");
    }

    Ok(payload)
}

pub fn build_checksum_packet(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHECKSUM_HEADER_LEN + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&adler32(payload).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn adler32(payload: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;

    for byte in payload {
        a = (a + (*byte as u32)) % MOD;
        b = (b + a) % MOD;
    }

    (b << 16) | a
}

pub fn decode_client_frame(packet: &[u8], tag_len: usize) -> ClientFrame<'_> {
    if packet.len() < COOKIE_MAGIC.len() || packet[..4] != COOKIE_MAGIC {
        return ClientFrame::RawPayload(packet);
    }

    let header_len = cookie_header_len(tag_len);
    if packet.len() < header_len {
        return ClientFrame::Malformed(FrameDecodeError::TooShort);
    }

    let version = packet[4];
    if version != COOKIE_VERSION {
        return ClientFrame::Malformed(FrameDecodeError::InvalidVersion);
    }

    let kind = packet[5];
    let issued_at_secs = u32::from_be_bytes([packet[6], packet[7], packet[8], packet[9]]);
    let nonce = u64::from_be_bytes([
        packet[10], packet[11], packet[12], packet[13], packet[14], packet[15], packet[16],
        packet[17],
    ]);

    let mac = &packet[COOKIE_HEADER_BASE_LEN..header_len];
    let payload = &packet[header_len..];

    match kind {
        COOKIE_KIND_CHALLENGE => ClientFrame::CookieChallenge,
        COOKIE_KIND_RESPONSE => ClientFrame::CookieResponse(CookieEnvelope {
            issued_at_secs,
            nonce,
            mac,
            payload,
        }),
        _ => ClientFrame::Malformed(FrameDecodeError::UnknownKind),
    }
}

pub fn build_response_packet_from_challenge(
    challenge_packet: &[u8],
    payload: &[u8],
    tag_len: usize,
) -> Option<Vec<u8>> {
    let header_len = cookie_header_len(tag_len);
    if challenge_packet.len() != header_len {
        return None;
    }

    if challenge_packet.get(0..4)? != COOKIE_MAGIC {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_raw_payload() {
        let payload = b"hello";
        let frame = decode_client_frame(payload, 16);
        match frame {
            ClientFrame::RawPayload(inner) => assert_eq!(inner, payload),
            _ => panic!("expected raw payload"),
        }
    }

    #[test]
    fn cookie_frame_too_short_is_malformed() {
        let data = b"NXCG\x01\x02";
        let frame = decode_client_frame(data, 16);
        match frame {
            ClientFrame::Malformed(FrameDecodeError::TooShort) => {}
            _ => panic!("expected malformed short frame"),
        }
    }

    #[test]
    fn packet_size_validation() {
        let limits = PacketLimits {
            min_packet_size: 3,
            max_packet_size: 10,
        };
        assert!(validate_packet_size(b"123", limits).is_ok());
        assert!(validate_packet_size(b"12", limits).is_err());
        assert!(validate_packet_size(&[0u8; 11], limits).is_err());
    }

    #[test]
    fn checksum_packet_validation_accepts_valid_frame() {
        let payload = b"SYNC:30|MMR:1200|DATA";
        let packet = build_checksum_packet(payload);
        let limits = PacketLimits {
            min_packet_size: 1,
            max_packet_size: 1500,
        };
        let policy = PacketValidationPolicy {
            enabled: true,
            strict_mode: true,
            require_checksum: true,
            strip_checksum_header: true,
        };

        let validated = validate_packet(&packet, limits, policy).expect("valid checksummed packet");
        assert_eq!(validated, payload);
    }

    #[test]
    fn checksum_packet_validation_rejects_tampered_frame() {
        let payload = b"MMR:1200";
        let mut packet = build_checksum_packet(payload);
        packet[4] ^= 0xAA;
        let limits = PacketLimits {
            min_packet_size: 1,
            max_packet_size: 1500,
        };
        let policy = PacketValidationPolicy {
            enabled: true,
            strict_mode: true,
            require_checksum: true,
            strip_checksum_header: true,
        };

        let err = validate_packet(&packet, limits, policy).expect_err("checksum must fail");
        assert_eq!(err, "checksum_mismatch");
    }
}
