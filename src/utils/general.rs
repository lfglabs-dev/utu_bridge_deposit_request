use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use starknet::core::types::Felt;

/// Get the current timestamp in milliseconds
#[allow(dead_code)]
pub fn get_current_timestamp() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_millis() as u64
}

#[allow(dead_code)]
pub fn to_hex(felt: &Felt) -> String {
    let bytes = felt.to_bytes_be();
    let mut result = String::with_capacity(bytes.len() * 2 + 2);
    result.push_str("0x");
    for byte in bytes {
        write!(&mut result, "{:02x}", byte).unwrap();
    }
    result
}
