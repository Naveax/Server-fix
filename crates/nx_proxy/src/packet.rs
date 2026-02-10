pub const COOKIE_MAGIC: [u8; 4] = *b"NXCG";
pub const COOKIE_VERSION: u8 = 1;
pub const COOKIE_KIND_CHALLENGE: u8 = 1;
pub const COOKIE_KIND_RESPONSE: u8 = 2;
pub const COOKIE_MIN_TAG_LEN: usize = 8;
pub const COOKIE_MAX_TAG_LEN: usize = 32;
pub const COOKIE_HEADER_BASE_LEN: usize = 4 + 1 + 1 + 4 + 8;

#[derive(Debug, Clone, Copy)]
pub struct PacketLimits {
    pub min_packet_size: usize,
    pub max_packet_size: usize,
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
}
