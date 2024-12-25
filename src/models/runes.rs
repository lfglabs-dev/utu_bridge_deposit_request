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
