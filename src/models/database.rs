use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositAddressDocument {
    pub starknet_address: String,
    pub bitcoin_deposit_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistedDepositDocument {
    pub tx_id: String,
}
