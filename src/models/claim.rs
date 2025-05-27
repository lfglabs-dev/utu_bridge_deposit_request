use serde::{Deserialize, Serialize};
use starknet::core::types::Felt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FordefiDepositData {
    pub rune_id_block: Felt,
    pub rune_id_tx: Felt,
    pub amount: (Felt, Felt),
    pub tx_id: String,
    pub tx_vout: usize,
    pub hashed_value: Felt,
    pub transaction_struct: Vec<Felt>,
    pub rune_contract: Felt,
    pub starknet_addr: String,
    pub vault_id: String,
}
