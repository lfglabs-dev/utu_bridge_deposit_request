use anyhow::{anyhow, Ok, Result};
use bitcoincore_rpc::bitcoin::hashes::Hash;
use bitcoincore_rpc::bitcoin::BlockHash;
use zmq::Message;

#[allow(dead_code)]
pub fn get_block_hash(msg: Message) -> Result<BlockHash> {
    let block_hash_bytes = msg.to_vec();
    if block_hash_bytes.len() == 32 {
        // Reverse the bytes to convert from Little Endian to Big Endian
        let block_hash_bytes_be: Vec<u8> = block_hash_bytes.iter().rev().cloned().collect();

        // Convert Vec<u8> to [u8; 32] after reversing
        let block_hash_array: [u8; 32] = block_hash_bytes_be
            .try_into()
            .expect("Failed to convert to [u8; 32]");

        let block_hash = BlockHash::from_raw_hash(Hash::from_byte_array(block_hash_array));
        Ok(block_hash)
    } else {
        Err(anyhow!(
            "Unexpected block hash length: {}",
            block_hash_bytes.len()
        ))
    }
}
