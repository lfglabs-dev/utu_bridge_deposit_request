use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedRuneDocument {
    pub id: String,
    pub name: String,
    pub spaced_name: String,
    pub number: u64,
    pub divisibility: u64,
    pub symbol: String,
    pub turbo: bool,
    pub mint_terms: Value,
    pub supply: Value,
    pub location: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuneDetail {
    pub divisibility: u64,
    pub rune_id: RuneId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuneId {
    pub block: u64,
    pub tx: u32,
}
