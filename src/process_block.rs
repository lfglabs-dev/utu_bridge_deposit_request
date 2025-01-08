use std::{env, str::FromStr, sync::Arc, time::Duration};

use anyhow::Result;
use bitcoin::{BlockHash, Txid};
use bitcoincore_rpc::{json::GetRawTransactionResult, RpcApi};
use reqwest::Client;
use serde_json::{json, Value};
use starknet::core::types::Felt;

use crate::{
    models::{
        claim::{ClaimCalldata, ClaimData, Signature},
        hiro::{BlockActivity, BlockActivityResult, Operation},
    },
    state::{database::DatabaseExt, transactions::TransactionBuilderStateTrait, AppState},
    utils::{
        calldata::{get_transaction_struct_felt, hex_to_hash_rev},
        runes::get_supported_runes_vec,
        Address,
    },
};

lazy_static::lazy_static! {
    static ref HIRO_API_URL: String = env::var("HIRO_API_URL").expect("HIRO_API_URL must be set");
    static ref HIRO_API_KEY: String = env::var("HIRO_API_KEY").expect("HIRO_API_KEY must be set");
    static ref UTU_API_URL: String = env::var("UTU_API_URL").expect("UTU_API_URL must be set");
    static ref HTTP_CLIENT: Client = Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .build()
        .expect("Failed to create HTTP client");
}

pub async fn process_block(state: &Arc<AppState>, block_hash: BlockHash) -> Result<()> {
    let mut session = match state.db.client().start_session().await {
        Ok(session) => session,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "Database error: unable to start session".to_string()
            ));
        }
    };
    if let Err(err) = session.start_transaction().await {
        return Err(anyhow::anyhow!("Database error: {:?}", err));
    };

    let supported_runes = get_supported_runes_vec(&state).await?;

    // Fetch block activity
    let mut offset = 0;
    let mut total = 0;
    loop {
        let url = format!(
            "{}/runes/v1/blocks/{}/activity?offset={}&limit=60",
            *HIRO_API_URL, block_hash, offset
        );
        let res = HTTP_CLIENT
            .get(url)
            .header("x-api-key", HIRO_API_KEY.clone())
            .send()
            .await?;

        if !res.status().is_success() {
            state
                .logger
                .warning(format!("Failed to get activity for block: {}", block_hash));
            continue;
        }

        let block_activity = res.json::<BlockActivity>().await?;
        total = block_activity.total;

        for tx in block_activity.results {
            // As we only need the deposit address to claim the runes on starknet we will check only for Receive operations
            // that have an address defined (corresponding to the receiver_address of the Receive operation)
            // and rune_id is in supported_runes
            if is_valid_receive_operation(&tx, &supported_runes) {
                let receiver_address = tx.address.clone().unwrap();

                // Check if the received_address is part of our deposit addresses
                if let Ok(starknet_addr) = state
                    .db
                    .is_deposit_addr(&mut session, receiver_address.clone())
                    .await
                {
                    // We process the deposit transaction and add it to the queue
                    if let Err(e) = process_deposit_transaction(
                        state,
                        &tx,
                        &receiver_address,
                        &starknet_addr,
                        &block_hash,
                    )
                    .await
                    {
                        state.logger.warning(format!(
                            "Failed to process deposit transaction for tx_id: {}: {:?}",
                            tx.location.tx_id, e
                        ));
                    }
                }
            }
        }

        // we fetch 60 txs at a time and a block can have more so
        // we continue fetching until we analyze all txs
        offset += 1;
        if total <= offset * 60 {
            break;
        }
    }

    state
        .logger
        .info(format!("Completed processing block: {}", block_hash));

    if let Err(err) = session.commit_transaction().await {
        return Err(anyhow::anyhow!("Database error: {:?}", err));
    };

    Ok(())
}

/// Determines if the transaction is a valid Receive operation.
pub fn is_valid_receive_operation(tx: &BlockActivityResult, supported_runes: &Vec<String>) -> bool {
    tx.operation == Operation::Receive
        && tx.address.is_some()
        && supported_runes.contains(&tx.rune.id)
}

/// Processes a valid deposit transaction.
pub async fn process_deposit_transaction(
    state: &Arc<AppState>,
    tx: &BlockActivityResult,
    receiver_addr: &String,
    starknet_addr: &String,
    block_hash: &BlockHash,
) -> Result<()> {
    let claim_data = match fetch_claim_data(tx, receiver_addr, starknet_addr).await {
        Ok(claim_data) => claim_data,
        Err(err) => {
            return Err(anyhow::anyhow!(format!(
                "Failed to fetch claim data : {:?}",
                err
            )))
        }
    };

    // Retrieve the complete transaction from bitcoin RPC
    // We need it to build the starknet transaction.
    match fetch_bitcoin_transaction_info(state, &tx.location.tx_id, block_hash) {
        Ok(tx_info) => {
            let transaction_struct = get_transaction_struct_felt(&state.bitcoin_provider, tx_info);
            let tx_id = match Txid::from_str(&claim_data.tx_id) {
                Ok(tx_id) => Some(tx_id),
                Err(_) => None,
            };
            // Add claim runes transaction to the queue
            state
                .transactions
                .add_transaction(ClaimCalldata {
                    rune_id: claim_data.rune_id,
                    amount: claim_data.amount,
                    target_addr: claim_data.target_addr,
                    sig: claim_data.sig,
                    tx_id: hex_to_hash_rev(tx_id),
                    tx_id_str: claim_data.tx_id,
                    transaction_struct,
                })
                .await;
        }
        Err(err) => {
            state.logger.warning(format!(
                "Failed to retrieve transaction data for tx_id: {}: {:?}",
                tx.location.tx_id, err
            ));
        }
    }
    Ok(())
}

/// Fetches claim data from the UTU API.
async fn fetch_claim_data(
    tx: &BlockActivityResult,
    receiver_address: &String,
    starknet_addr: &String,
) -> Result<ClaimData> {
    let url = format!("{}/claim_deposit_data", *UTU_API_URL);
    let payload = json!({
        "starknet_addr": starknet_addr,
        "tx_id": tx.location.tx_id,
        "tx_vout": tx.location.vout,
    });
    let claim_res = HTTP_CLIENT.post(&url).json(&payload).send().await?;
    if claim_res.status().is_success() {
        // let claim_data = claim_res.json::<ClaimDepositDataRes>().await?;
        let claim_data_value = claim_res.json::<Value>().await?;

        // Extract fields manually because deserialization directly to Felt is failing.
        let claim_data = claim_data_value["data"].as_object().unwrap();
        let rune_id = Felt::from_dec_str(claim_data["rune_id"].as_str().unwrap())?;
        let amount = (
            Felt::from_dec_str(claim_data["amount"][0].as_str().unwrap())?,
            Felt::from_dec_str(claim_data["amount"][1].as_str().unwrap())?,
        );
        let target_addr = Felt::from_hex(claim_data["target_addr"].as_str().unwrap())?;
        let tx_id = claim_data["tx_id"].as_str().unwrap().to_string();
        let sig = Signature {
            r: Felt::from_dec_str(claim_data["sig"]["r"].as_str().unwrap())?,
            s: Felt::from_dec_str(claim_data["sig"]["s"].as_str().unwrap())?,
        };
        Ok(ClaimData {
            rune_id,
            amount,
            target_addr: Address { felt: target_addr },
            tx_id,
            sig,
        })
    } else {
        Err(anyhow::anyhow!(
            "Failed to retrieve claim data for deposit address: {} with error: {:?}",
            receiver_address,
            claim_res.text().await
        ))
    }
}

/// Fetches transaction data from the Bitcoin RPC provider.
fn fetch_bitcoin_transaction_info(
    state: &Arc<AppState>,
    tx_id: &str,
    block_hash: &BlockHash,
) -> Result<GetRawTransactionResult> {
    state
        .bitcoin_provider
        .get_raw_transaction_info(&Txid::from_str(tx_id)?, Some(block_hash))
        .map_err(|e| e.into())
}
