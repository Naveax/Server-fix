#![no_main]

use libfuzzer_sys::fuzz_target;
use nx_proxy::packet::decode_client_frame;

fuzz_target!(|data: &[u8]| {
    let _ = decode_client_frame(data, 16);
});
