use std::io;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const LENGTH_PREFIX_BYTES: usize = 2;
// From RLBot `corepacket.fbs` `CoreMessage` union ordering (`None` = 0).
const CORE_MESSAGE_BALL_PREDICTION: u8 = 6;
const CORE_MESSAGE_RENDERING_STATUS: u8 = 8;
const CORE_MESSAGE_PING_REQUEST: u8 = 9;
const CORE_MESSAGE_PING_RESPONSE: u8 = 10;
// From RLBot `interfacepacket.fbs` `InterfaceMessage` union ordering (`None` = 0).
const INTERFACE_MESSAGE_PLAYER_INPUT: u8 = 4;
const INTERFACE_MESSAGE_DESIRED_GAME_STATE: u8 = 5;
const INTERFACE_MESSAGE_RENDER_GROUP: u8 = 6;
const INTERFACE_MESSAGE_REMOVE_RENDER_GROUP: u8 = 7;
const INTERFACE_MESSAGE_MATCH_COMM: u8 = 8;
const INTERFACE_MESSAGE_CONNECTION_SETTINGS: u8 = 9;
const INTERFACE_MESSAGE_STOP_COMMAND: u8 = 10;
const INTERFACE_MESSAGE_INIT_COMPLETE: u8 = 12;
const INTERFACE_MESSAGE_RENDERING_STATUS: u8 = 13;
const INTERFACE_MESSAGE_PING_REQUEST: u8 = 14;
const INTERFACE_MESSAGE_PING_RESPONSE: u8 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameClass {
    Telemetry,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDirection {
    InterfaceToCore,
    CoreToInterface,
}

pub fn classify_frame(payload: &[u8], direction: FrameDirection) -> FrameClass {
    match direction {
        FrameDirection::InterfaceToCore => classify_interface_frame(payload),
        FrameDirection::CoreToInterface => classify_core_frame(payload),
    }
}

fn classify_interface_frame(payload: &[u8]) -> FrameClass {
    match parse_interface_message_type(payload) {
        // Rendering is optional visualization and can be shed under pressure.
        Some(
            INTERFACE_MESSAGE_RENDER_GROUP
            | INTERFACE_MESSAGE_REMOVE_RENDER_GROUP
            | INTERFACE_MESSAGE_MATCH_COMM
            | INTERFACE_MESSAGE_RENDERING_STATUS,
        ) => FrameClass::Telemetry,
        // Explicit control-path messages always stay critical.
        Some(
            INTERFACE_MESSAGE_PLAYER_INPUT
            | INTERFACE_MESSAGE_CONNECTION_SETTINGS
            | INTERFACE_MESSAGE_INIT_COMPLETE
            | INTERFACE_MESSAGE_STOP_COMMAND
            | INTERFACE_MESSAGE_DESIRED_GAME_STATE
            | INTERFACE_MESSAGE_PING_REQUEST
            | INTERFACE_MESSAGE_PING_RESPONSE,
        ) => FrameClass::Critical,
        // Fail-safe for parse failure or unlisted/new message types.
        Some(_) | None => FrameClass::Critical,
    }
}

fn classify_core_frame(payload: &[u8]) -> FrameClass {
    match parse_core_message_type(payload) {
        // Ball prediction and auxiliary status/latency signals can be treated as telemetry.
        Some(
            CORE_MESSAGE_BALL_PREDICTION
            | CORE_MESSAGE_RENDERING_STATUS
            | CORE_MESSAGE_PING_REQUEST
            | CORE_MESSAGE_PING_RESPONSE,
        ) => FrameClass::Telemetry,
        // Fail-safe for parse failure or unlisted/new message types.
        Some(_) | None => FrameClass::Critical,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedFrame<'a> {
    pub payload: &'a [u8],
    pub consumed_bytes: usize,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SliceDecodeError {
    #[error("need more bytes")]
    NeedMoreData,
    #[error("frame length must be > 0")]
    LengthZero,
    #[error("frame length {declared_bytes} exceeds max {max_frame_bytes}")]
    Oversized {
        declared_bytes: usize,
        max_frame_bytes: usize,
    },
}

pub fn decode_frame_from_slice<'a>(
    data: &'a [u8],
    max_frame_bytes: usize,
) -> Result<DecodedFrame<'a>, SliceDecodeError> {
    if data.len() < LENGTH_PREFIX_BYTES {
        return Err(SliceDecodeError::NeedMoreData);
    }

    let declared_bytes = u16::from_be_bytes([data[0], data[1]]) as usize;

    if declared_bytes == 0 {
        return Err(SliceDecodeError::LengthZero);
    }

    if declared_bytes > max_frame_bytes {
        return Err(SliceDecodeError::Oversized {
            declared_bytes,
            max_frame_bytes,
        });
    }

    let frame_end = LENGTH_PREFIX_BYTES + declared_bytes;
    if data.len() < frame_end {
        return Err(SliceDecodeError::NeedMoreData);
    }

    Ok(DecodedFrame {
        payload: &data[LENGTH_PREFIX_BYTES..frame_end],
        consumed_bytes: frame_end,
    })
}

#[derive(Debug, Error)]
pub enum FrameReadError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("frame length must be > 0")]
    LengthZero,
    #[error("frame length {declared_bytes} exceeds max {max_frame_bytes}")]
    Oversized {
        declared_bytes: usize,
        max_frame_bytes: usize,
    },
    #[error("incomplete frame")]
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadFrame {
    EndOfStream,
    Frame(Vec<u8>),
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> Result<ReadFrame, FrameReadError> {
    let Some(declared_bytes) = read_length_prefix(reader).await? else {
        return Ok(ReadFrame::EndOfStream);
    };

    if declared_bytes == 0 {
        return Err(FrameReadError::LengthZero);
    }

    if declared_bytes > max_frame_bytes {
        return Err(FrameReadError::Oversized {
            declared_bytes,
            max_frame_bytes,
        });
    }

    let mut payload = vec![0u8; declared_bytes];
    match reader.read_exact(&mut payload).await {
        Ok(_) => Ok(ReadFrame::Frame(payload)),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(FrameReadError::Incomplete),
        Err(err) => Err(FrameReadError::Io(err)),
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let len_u16 = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    writer.write_all(&len_u16.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

async fn read_length_prefix<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<usize>, FrameReadError> {
    let mut header = [0u8; LENGTH_PREFIX_BYTES];
    let mut read = 0usize;

    while read < LENGTH_PREFIX_BYTES {
        let n = reader.read(&mut header[read..]).await?;
        if n == 0 {
            if read == 0 {
                return Ok(None);
            }
            return Err(FrameReadError::Incomplete);
        }
        read += n;
    }

    Ok(Some(u16::from_be_bytes(header) as usize))
}

fn parse_core_message_type(payload: &[u8]) -> Option<u8> {
    parse_packet_message_type(payload)
}

fn parse_interface_message_type(payload: &[u8]) -> Option<u8> {
    parse_packet_message_type(payload)
}

fn parse_packet_message_type(payload: &[u8]) -> Option<u8> {
    const MESSAGE_TYPE_FIELD_INDEX: usize = 0;
    parse_table_u8_field(payload, MESSAGE_TYPE_FIELD_INDEX)
}

fn parse_table_u8_field(payload: &[u8], field_index: usize) -> Option<u8> {
    let root_table_start = read_u32_le(payload, 0)? as usize;
    let vtable_offset = read_i32_le(payload, root_table_start)?;
    if vtable_offset <= 0 {
        return None;
    }

    let vtable_start = root_table_start.checked_sub(vtable_offset as usize)?;
    let vtable_len = read_u16_le(payload, vtable_start)? as usize;
    if vtable_len < 4 {
        return None;
    }

    let field_entry = vtable_start.checked_add(4 + field_index * 2)?;
    let vtable_end = vtable_start.checked_add(vtable_len)?;
    if field_entry.checked_add(2)? > vtable_end {
        return None;
    }

    let field_offset = read_u16_le(payload, field_entry)? as usize;
    if field_offset == 0 {
        return None;
    }

    let field_pos = root_table_start.checked_add(field_offset)?;
    payload.get(field_pos).copied()
}

fn read_u16_le(payload: &[u8], pos: usize) -> Option<u16> {
    let bytes = payload.get(pos..pos.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(payload: &[u8], pos: usize) -> Option<u32> {
    let bytes = payload.get(pos..pos.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_i32_le(payload: &[u8], pos: usize) -> Option<i32> {
    let bytes = payload.get(pos..pos.checked_add(4)?)?;
    Some(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_frame_from_slice_accepts_valid_frame() {
        let mut data = vec![];
        data.extend_from_slice(&(3u16.to_be_bytes()));
        data.extend_from_slice(&[0x02, 0xaa, 0xbb]);

        let decoded = decode_frame_from_slice(&data, 1024).expect("frame should decode");
        assert_eq!(decoded.payload, &[0x02, 0xaa, 0xbb]);
        assert_eq!(decoded.consumed_bytes, 5);
    }

    #[test]
    fn decode_frame_from_slice_rejects_oversized() {
        let mut data = vec![];
        data.extend_from_slice(&(2048u16.to_be_bytes()));
        data.extend_from_slice(&[0u8; 4]);

        let err =
            decode_frame_from_slice(&data, 1024).expect_err("oversized frame should be rejected");
        assert!(matches!(
            err,
            SliceDecodeError::Oversized {
                declared_bytes: 2048,
                max_frame_bytes: 1024
            }
        ));
    }

    #[test]
    fn classify_frame_uses_message_type_by_direction() {
        let ball_prediction = build_message_packet_with_message_type(CORE_MESSAGE_BALL_PREDICTION);
        assert_eq!(
            classify_frame(&ball_prediction, FrameDirection::CoreToInterface),
            FrameClass::Telemetry
        );

        let game_packet = build_message_packet_with_message_type(2);
        assert_eq!(
            classify_frame(&game_packet, FrameDirection::CoreToInterface),
            FrameClass::Critical
        );

        let render_group = build_message_packet_with_message_type(INTERFACE_MESSAGE_RENDER_GROUP);
        assert_eq!(
            classify_frame(&render_group, FrameDirection::InterfaceToCore),
            FrameClass::Telemetry
        );

        let player_input = build_message_packet_with_message_type(INTERFACE_MESSAGE_PLAYER_INPUT);
        assert_eq!(
            classify_frame(&player_input, FrameDirection::InterfaceToCore),
            FrameClass::Critical
        );

        let init_complete = build_message_packet_with_message_type(INTERFACE_MESSAGE_INIT_COMPLETE);
        assert_eq!(
            classify_frame(&init_complete, FrameDirection::InterfaceToCore),
            FrameClass::Critical
        );

        let connection_settings =
            build_message_packet_with_message_type(INTERFACE_MESSAGE_CONNECTION_SETTINGS);
        assert_eq!(
            classify_frame(&connection_settings, FrameDirection::InterfaceToCore),
            FrameClass::Critical
        );

        assert_eq!(
            classify_frame(&[], FrameDirection::InterfaceToCore),
            FrameClass::Critical
        );
        assert_eq!(
            classify_frame(&[0x00], FrameDirection::CoreToInterface),
            FrameClass::Critical
        );
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_frame() {
        use tokio::io::{duplex, AsyncWriteExt};

        let (mut writer, mut reader) = duplex(64);
        writer
            .write_all(&2048u16.to_be_bytes())
            .await
            .expect("write length prefix");

        let err = read_frame(&mut reader, 1024)
            .await
            .expect_err("oversized frame should be rejected");
        assert!(matches!(
            err,
            FrameReadError::Oversized {
                declared_bytes: 2048,
                max_frame_bytes: 1024
            }
        ));
    }

    fn build_message_packet_with_message_type(message_type: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 24];

        // Root uoffset points to table start.
        buf[0..4].copy_from_slice(&12u32.to_le_bytes());

        // Vtable at offset 4, table at offset 12.
        buf[4..6].copy_from_slice(&8u16.to_le_bytes()); // vtable size
        buf[6..8].copy_from_slice(&12u16.to_le_bytes()); // object size
        buf[8..10].copy_from_slice(&4u16.to_le_bytes()); // message_type field offset
        buf[10..12].copy_from_slice(&8u16.to_le_bytes()); // message union field offset

        // Table body.
        buf[12..16].copy_from_slice(&8i32.to_le_bytes()); // vtable back-offset
        buf[16] = message_type; // message_type field

        // union object offset is left as 0 (not needed for classification)

        buf
    }
}
