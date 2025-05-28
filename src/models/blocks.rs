use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockWithTransactions {
    pub hash: String,
    pub confirmations: i64,
    pub height: u64,
    pub version: u64,
    #[serde(rename = "versionHex")]
    pub version_hex: String,
    pub merkleroot: String,
    pub time: u64,
    pub mediantime: u64,
    pub nonce: u64,
    pub bits: String,
    pub difficulty: f64,
    pub chainwork: String,
    #[serde(rename = "nTx")]
    pub n_tx: u64,
    pub previousblockhash: String,
    pub strippedsize: u64,
    pub size: u64,
    pub weight: u64,
    pub tx: Vec<Transaction>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub txid: String,
    pub hash: String,
    pub version: u64,
    pub size: u64,
    pub vsize: u64,
    pub weight: u64,
    pub locktime: u64,
    pub vin: Vec<Vin>,
    pub vout: Vec<Vout>,
    pub hex: String,
    pub confirmations: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vin {
    pub txid: Option<String>,
    pub vout: Option<u64>,
    #[serde(rename = "scriptSig")]
    pub script_sig: Option<ScriptSig>,
    pub sequence: u64,
    pub txinwitness: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScriptSig {
    pub asm: String,
    pub hex: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vout {
    pub value: f64,
    pub n: u64,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptPubKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScriptPubKey {
    pub asm: String,
    pub hex: String,
    #[serde(rename = "reqSigs")]
    pub req_sigs: Option<u64>,
    #[serde(rename = "type")]
    pub script_type: String,
    pub addresses: Option<Vec<String>>,
}
