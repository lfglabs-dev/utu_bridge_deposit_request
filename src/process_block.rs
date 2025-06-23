use std::{collections::HashMap, env, str::FromStr, sync::Arc, time::Duration};

use anyhow::Result;
use bitcoin::{Address, Block, BlockHash, Network, Txid};
use bitcoincore_rpc::{json::GetRawTransactionResult, RpcApi};
use mongodb::{bson::DateTime, ClientSession};
use reqwest::Client;
use tokio::time::sleep;
use utu_bridge_types::bitcoin::{BitcoinAddress, BitcoinRuneId, BitcoinTxId};

use crate::{
    models::{
        blocks::BlockWithTransactions,
        claim::FordefiDepositData,
        monitor::{FordefiId, FordefiTransaction, TransactionType},
        output::{OrdOutputResult, OutputToProcess},
    },
    state::{database::DatabaseExt, AppState},
    utils::{
        calldata::get_transaction_struct_felt,
        fordefi::send_fordefi_request,
        starknet::{compute_hashed_value, compute_rune_contract},
    },
};

lazy_static::lazy_static! {
    static ref ORD_NODE_URL: String = env::var("ORD_NODE_URL").expect("ORD_NODE_URL must be set");
    static ref ORD_TIMEOUT_MS: u64 = env::var("ORD_TIMEOUT_MS").expect("ORD_TIMEOUT_MS must be set").parse::<u64>().expect("ORD_TIMEOUT_MS must be a valid u64");
    static ref HTTP_CLIENT: Client = Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .build()
        .expect("Failed to create HTTP client");

    static ref HTTP_SKIP_CERT_CHECK: Client = Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to create HTTP client");
    static ref FORDEFI_DEPOSIT_VAULT_ID: String = env::var("FORDEFI_DEPOSIT_VAULT_ID").expect("FORDEFI_DEPOSIT_VAULT_ID must be set");
    static ref MIN_CONFIRMATIONS: i64 = env::var("MIN_CONFIRMATIONS").expect("MIN_CONFIRMATIONS must be set").parse::<i64>().expect("MIN_CONFIRMATIONS must be a valid i64");
    static ref POLLING_BLOCK_DELAY_SEC: u64 = env::var("POLLING_BLOCK_DELAY_SEC").expect("POLLING_BLOCK_DELAY_SEC must be set").parse::<u64>().expect("POLLING_BLOCK_DELAY_SEC must be a valid u64");
    static ref ORD_API_RETRY_DELAY_SEC: u64 = env::var("ORD_API_RETRY_DELAY_SEC").expect("ORD_API_RETRY_DELAY_SEC must be set").parse::<u64>().expect("ORD_API_RETRY_DELAY_SEC must be a valid u64");
    static ref ORD_API_RETRY_MAX_ATTEMPTS: u64 = env::var("ORD_API_RETRY_MAX_ATTEMPTS").expect("ORD_API_RETRY_MAX_ATTEMPTS must be set").parse::<u64>().expect("ORD_API_RETRY_MAX_ATTEMPTS must be a valid u64");
}

pub async fn get_block_from_rpc(
    state: &Arc<AppState>,
    block_hash_value: serde_json::Value,
) -> Result<BlockWithTransactions> {
    let mut attempts = 0;
    let max_attempts = 3;
    loop {
        match state
            .bitcoin_provider
            .call::<BlockWithTransactions>("getblock", &[block_hash_value.clone(), 2.into()])
        {
            Ok(block_from_rpc) => return Ok(block_from_rpc),
            Err(e) => {
                attempts += 1;
                if attempts > max_attempts {
                    return Err(anyhow::anyhow!(e));
                }
                sleep(Duration::from_secs(*POLLING_BLOCK_DELAY_SEC)).await;
                continue;
            }
        };
    }
}

pub async fn parse_block(
    state: &Arc<AppState>,
    session: &mut ClientSession,
    block_height: u64,
    block: Block,
    supported_runes: Vec<String>,
) -> Result<Vec<OutputToProcess>> {
    let mut outputs_to_process: Vec<OutputToProcess> = vec![];

    state.logger.info(format!(
        "[{}] Processing {} transactions",
        block_height,
        block.txdata.len()
    ));

    // parse to all the outputs, and check the ones that concerns us
    for (tx_index, tx) in block.txdata.iter().enumerate() {
        // Log progress every 100 transactions
        if tx_index % 100 == 0 {
            let percentage = (tx_index * 100) / block.txdata.len();
            state.logger.info(format!(
                "[{}] Progress: {}%, processed {} out of {} transactions",
                block_height,
                percentage,
                tx_index,
                block.txdata.len()
            ));
        }

        for (output_index, vout) in tx.output.iter().enumerate() {
            // Check on ord if the output contains supported runes
            let txid = tx.compute_txid();
            match get_ord_data(txid.to_string(), output_index).await {
                Ok(ord_data) => {
                    for (rune_spaced_name, rune_data) in ord_data.runes.clone() {
                        if supported_runes.contains(&rune_spaced_name) {
                            // Check if the output is one of our deposit addresses
                            if let Ok(receiver_address) =
                                Address::from_script(&vout.script_pubkey, Network::Bitcoin)
                            {
                                let btc_receiver_address = BitcoinAddress::new(
                                    &receiver_address.to_string(),
                                    Network::Bitcoin,
                                )?;

                                if state
                                    .blacklisted_deposit_addr
                                    .contains(&btc_receiver_address)
                                {
                                    continue;
                                }

                                if let Ok(starknet_addr) =
                                    state.db.is_deposit_addr(btc_receiver_address.clone()).await
                                {
                                    // Check if the transaction was already submitted
                                    if state
                                        .db
                                        .was_submitted(session, txid.to_string(), output_index)
                                        .await?
                                    {
                                        continue;
                                    }

                                    outputs_to_process.push(OutputToProcess {
                                        rune_spaced_name,
                                        rune_data,
                                        txid: txid.to_string(),
                                        output_index,
                                        starknet_addr,
                                    });
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    state.logger.warning(format!(
                        "[{}] Failed to get ord data for txid: {} and output_index: {} with error: {:?}",
                        block_height, txid, output_index, err
                    ));
                }
            }
        }
    }
    Ok(outputs_to_process)
}

pub async fn wait_for_block_confirmation(
    state: &Arc<AppState>,
    block_hash_value: serde_json::Value,
) -> Result<()> {
    loop {
        let block_from_rpc = get_block_from_rpc(state, block_hash_value.clone()).await?;
        if block_from_rpc.confirmations >= *MIN_CONFIRMATIONS {
            return Ok(());
        } else if block_from_rpc.confirmations == -1 {
            return Err(anyhow::anyhow!(
                "Block was not integrated (confirmations = -1), stopping task"
            ));
        } else {
            sleep(Duration::from_secs(*POLLING_BLOCK_DELAY_SEC)).await;
        }
    }
}

pub async fn process_output(
    state: &Arc<AppState>,
    session: &mut ClientSession,
    output: OutputToProcess,
    block_hash: BlockHash,
    runes_mapping: &HashMap<String, (BitcoinRuneId, u32)>,
) -> Result<()> {
    // Compute hash_value needed for fordefi signature
    let (hashed_value, rune_id_block_felt, rune_id_tx_felt, amount_u256) = if let Ok(hashed_value) =
        compute_hashed_value(
            runes_mapping,
            output.rune_spaced_name.clone(),
            output.rune_data.amount,
            &output.txid,
            &output.starknet_addr,
        ) {
        hashed_value
    } else {
        return Err(anyhow::anyhow!(
            "Failed to compute hashed value for output: {}:{}",
            output.txid,
            output.output_index
        ));
    };

    // Retrieve the complete transaction from bitcoin RPC
    // We need it to build the starknet transaction.
    match fetch_bitcoin_transaction_info(state, &output.txid, &block_hash) {
        Ok(tx_info) => {
            let transaction_struct = get_transaction_struct_felt(&state.bitcoin_provider, tx_info);

            // we send the deposit request to fordefi
            let deposit_data = FordefiDepositData {
                rune_id_block: rune_id_block_felt,
                rune_id_tx: rune_id_tx_felt,
                amount: amount_u256,
                hashed_value,
                tx_id: output.txid.clone(),
                tx_vout: output.output_index,
                transaction_struct,
                rune_contract: compute_rune_contract(rune_id_block_felt, rune_id_tx_felt),
                starknet_addr: output.starknet_addr.to_string(),
                vault_id: FORDEFI_DEPOSIT_VAULT_ID.clone(),
            };

            match send_fordefi_request(deposit_data).await {
                Ok(fordefi_id) => {
                    state
                        .logger
                        .debug(format!("Processed with Fordefi tx-id: {}", fordefi_id));
                    // store the fordefi_id in the database
                    let fordefi_tx = FordefiTransaction {
                        btc_txid: BitcoinTxId::new(&output.txid).unwrap(),
                        fordefi_ids: vec![FordefiId {
                            id: fordefi_id,
                            vault_id: FORDEFI_DEPOSIT_VAULT_ID.clone(),
                        }],
                        sent_at: DateTime::now(),
                        tx_type: TransactionType::Deposit,
                    };
                    state.db.store_fordefi_txs(session, fordefi_tx).await?;
                }
                Err(err) => {
                    state.logger.severe(format!(
                        "Failed to send fordefi request for txid: {}:{} with error: {:?}",
                        output.txid, output.output_index, err
                    ));
                }
            }
        }
        Err(err) => {
            state.logger.warning(format!(
                "Failed to retrieve transaction data for txid: {}:{} with error: {:?}",
                output.txid, output.output_index, err
            ));
        }
    }

    Ok(())
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

/// Queries the ord API to get the number of runes in a given output
pub async fn get_ord_data(txid: String, vout: usize) -> Result<OrdOutputResult> {
    let mut attempts = 0;
    loop {
        let url = format!("http://{}/output/{}:{}", *ORD_NODE_URL, txid, vout);
        match HTTP_SKIP_CERT_CHECK
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(response) => {
                if !response.status().is_success() {
                    attempts += 1;
                    if attempts > *ORD_API_RETRY_MAX_ATTEMPTS {
                        return Err(anyhow::anyhow!(
                            "Failed to query ord API for {}:{}, status: {}",
                            txid,
                            vout,
                            response.status()
                        ));
                    }
                    let delay = *ORD_API_RETRY_DELAY_SEC * (2_u64.pow(attempts as u32));
                    sleep(Duration::from_secs(delay)).await;
                    continue;
                }
                let ord_output: OrdOutputResult = response.json().await?;
                return Ok(ord_output);
            }
            Err(err) => {
                attempts += 1;
                if attempts > *ORD_API_RETRY_MAX_ATTEMPTS {
                    return Err(anyhow::anyhow!(err));
                }
                let delay = *ORD_API_RETRY_DELAY_SEC * (2_u64.pow(attempts as u32));
                sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}
