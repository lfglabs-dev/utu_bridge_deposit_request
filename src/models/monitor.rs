use mongodb::bson::DateTime;
use serde::{Deserialize, Serialize};
use utu_bridge_types::bitcoin::BitcoinTxId;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FordefiTransaction {
    pub btc_txid: BitcoinTxId,
    pub fordefi_ids: Vec<FordefiId>,
    pub sent_at: DateTime,
    pub tx_type: TransactionType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FordefiId {
    pub id: String,
    pub vault_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransactionType {
    Withdraw,
    Deposit,
}
