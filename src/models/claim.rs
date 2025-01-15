use serde::{Deserialize, Serialize};
use starknet::core::types::Felt;

use crate::utils::Address;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimDepositDataRes {
    pub status: String,
    pub data: ClaimData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub r: Felt,
    pub s: Felt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimData {
    pub rune_id: Felt,
    pub amount: (Felt, Felt),
    pub target_addr: Address,
    pub tx_id: String,
    pub tx_vout: u32,
    pub sig: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimCalldata {
    pub rune_id: Felt,
    pub amount: (Felt, Felt),
    pub target_addr: Address,
    pub tx_id: Vec<Felt>,
    pub tx_id_str: String,
    pub tx_vout: Felt,
    pub sig: Signature,
    pub transaction_struct: Vec<Felt>,
}
