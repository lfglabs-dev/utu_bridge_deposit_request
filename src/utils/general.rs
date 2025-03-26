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

/// Validates a Bitcoin transaction ID
/// Returns true if the transaction ID is valid (contains only hex characters and is at least 1 character long)
pub fn is_valid_tx_id(tx_id: &str) -> bool {
    // Check if the string is empty
    if tx_id.is_empty() {
        return false;
    }

    // Check if the string is a valid txid
    if tx_id.len() > 64 {
        return false;
    }

    // Check if all characters are valid hex characters (0-9, a-f, A-F)
    tx_id.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_tx_ids() {
        // Standard 64-character txid
        assert!(is_valid_tx_id(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));

        // Same txid with uppercase letters
        assert!(is_valid_tx_id(
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        ));

        // Mixed case
        assert!(is_valid_tx_id(
            "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF"
        ));

        // Shorter valid txid (partial)
        assert!(is_valid_tx_id("0123456789abcdef"));

        // Single character
        assert!(is_valid_tx_id("a"));

        // All zeros
        assert!(is_valid_tx_id(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));

        // All f's
        assert!(is_valid_tx_id(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
    }

    #[test]
    fn test_invalid_tx_ids() {
        // Empty string
        assert!(!is_valid_tx_id(""));

        // Too long (65 characters)
        assert!(!is_valid_tx_id(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
        ));

        // Contains non-hex characters
        assert!(!is_valid_tx_id(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"
        ));
        assert!(!is_valid_tx_id(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde/"
        ));
        assert!(!is_valid_tx_id(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde "
        ));

        // Contains spaces
        assert!(!is_valid_tx_id("0123456789abcdef 0123456789abcdef"));

        // Contains special characters
        assert!(!is_valid_tx_id("0123456789abcdef-0123456789abcdef"));
        assert!(!is_valid_tx_id("0123456789abcdef/0123456789abcdef"));
    }

    #[test]
    fn test_padded_and_trimmed_tx_ids() {
        // Padded with zeros
        assert!(is_valid_tx_id(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ));

        // Leading zeros trimmed
        assert!(is_valid_tx_id("1"));
        assert!(is_valid_tx_id("a"));

        // Mixed padding
        assert!(is_valid_tx_id(
            "000000000000000000000000000000000000000000000000000000000000000a"
        ));

        // All zeros with different lengths
        assert!(is_valid_tx_id("0"));
        assert!(is_valid_tx_id("00"));
        assert!(is_valid_tx_id("000"));
        assert!(is_valid_tx_id("0000"));
    }
}
