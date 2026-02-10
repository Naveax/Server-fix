#![no_main]

use libfuzzer_sys::fuzz_target;
use nx_fbs_guard::codec::{classify_frame, decode_frame_from_slice, FrameDirection};

fuzz_target!(|data: &[u8]| {
    if data.len() >= 2 {
        let declared = u16::from_be_bytes([data[0], data[1]]) as usize;
        if declared > 0 && data.len() >= 2 + declared {
            let frame = &data[..2 + declared];
            if let Ok(decoded) = decode_frame_from_slice(frame, 1024) {
                let _ = classify_frame(decoded.payload, FrameDirection::InterfaceToCore);
                let _ = classify_frame(decoded.payload, FrameDirection::CoreToInterface);
            }
        }
    }

    if let Ok(decoded) = decode_frame_from_slice(data, 1024) {
        let _ = classify_frame(decoded.payload, FrameDirection::InterfaceToCore);
        let _ = classify_frame(decoded.payload, FrameDirection::CoreToInterface);
    }
});
