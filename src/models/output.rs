use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utu_bridge_types::{
    bitcoin::{BitcoinAddress, BitcoinOutpoint, BitcoinTxId},
    starknet::StarknetAddress,
    ClaimedRunesDepositsDocument, DepositClaimTxsDocument,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrdOutputResult {
    pub address: Option<BitcoinAddress>,
    pub indexed: bool,
    pub inscriptions: Vec<serde_json::Value>,
    pub outpoint: BitcoinOutpoint,
    pub runes: HashMap<String, OrdRune>,
    pub sat_ranges: Option<Vec<Vec<u128>>>,
    pub script_pubkey: String,
    pub spent: bool,
    pub transaction: BitcoinTxId,
    pub value: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrdRune {
    pub amount: u128,
    pub divisibility: u8,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyDeposit {
    pub bitcoin_deposit_address: Option<BitcoinAddress>,
    pub claimed_runes_deposits: Vec<ClaimedRunesDepositsDocument>,
    pub deposit_claim_txs: Vec<DepositClaimTxsDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputToProcess {
    pub rune_spaced_name: String,
    pub rune_data: OrdRune,
    pub txid: String,
    pub output_index: usize,
    pub starknet_addr: StarknetAddress,
}
