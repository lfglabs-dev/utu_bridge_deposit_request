use starknet::core::types::Felt;

#[derive(Debug, Eq, PartialEq)]
pub struct ByteArray {
    pub data: Vec<Felt>,         // 31-byte chunks as felts
    pub pending_word: Felt,      // Remaining bytes
    pub pending_word_len: usize, // Number of bytes in pending_word
}

impl ByteArray {
    pub fn from_u8_array(array: &[u8]) -> Self {
        const BYTE31_LEN: usize = 31; // Define the size of chunks (31 bytes)
        let chunks = array.chunks(BYTE31_LEN);

        let mut data = Vec::new();
        let mut last_chunk = Vec::new();

        // Process each chunk
        for chunk in chunks.clone() {
            if chunk.len() == BYTE31_LEN {
                data.push(Felt::from_bytes_be_slice(chunk));
            } else {
                last_chunk.extend_from_slice(chunk);
            }
        }

        // Handle the last chunk (if it's incomplete)
        let (pending_word, pending_word_len) = if !last_chunk.is_empty() {
            let mut padded_chunk = [0u8; BYTE31_LEN];
            padded_chunk[..last_chunk.len()].copy_from_slice(&last_chunk);

            (
                Felt::from_bytes_be_slice(&padded_chunk[..last_chunk.len()]), // Convert only meaningful bytes to Felt
                last_chunk.len(), // Length of the meaningful bytes
            )
        } else {
            // No pending bytes
            (Felt::ZERO, 0)
        };

        Self {
            data,
            pending_word,
            pending_word_len,
        }
    }

    pub fn to_calldata(array: &[u8]) -> Vec<Felt> {
        let byte_array = ByteArray::from_u8_array(array);
        let mut calldata = Vec::new();

        // Add the count of 31-byte chunks
        if byte_array.data.is_empty() {
            calldata.push(Felt::ZERO);
        } else {
            calldata.push(Felt::from(byte_array.data.len() as u32));
            calldata.extend(byte_array.data.iter());
        }

        // Add the pending word and its length
        calldata.push(byte_array.pending_word);
        calldata.push(Felt::from(byte_array.pending_word_len as u32));

        calldata
    }
}
