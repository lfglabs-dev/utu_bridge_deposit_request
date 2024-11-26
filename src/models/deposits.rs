use mongodb::bson::DateTime;
use serde::{Deserialize, Serialize};

use super::hiro::Rune;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositDocument {
    pub starknet_address: String,
    pub bitcoin_deposit_address: String,
    pub bitcoin_sender_address: String,
    pub tx_id: String,
    pub rune: Rune,
    pub amount: String,
    pub claimed: bool,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}
