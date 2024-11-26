use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockActivity {
    pub limit: u64,
    pub offset: u64,
    pub total: u64,
    pub results: Vec<BlockActivityResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockActivityResult {
    pub rune: Rune,
    pub address: Option<String>,
    pub receiver_address: Option<String>,
    pub amount: Option<String>,
    pub operation: Operation,
    pub location: Location,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")] // Ensures case-insensitive matching
pub enum Operation {
    Etching,
    Mint,
    Burn,
    Send,
    Receive,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rune {
    pub id: String,
    pub name: String,
    pub spaced_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub block_hash: String,
    pub block_height: u64,
    pub tx_id: String,
    pub tx_index: u64,
    pub vout: Option<u64>,
    pub output: Option<String>,
    pub timestamp: u64,
}
