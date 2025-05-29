use std::{collections::HashMap, env, str::FromStr, sync::Arc, time::Duration};

use anyhow::Result;
use bitcoin::{Address, Block, BlockHash, Network, Txid};
use bitcoincore_rpc::{json::GetRawTransactionResult, RpcApi};
use mongodb::{bson::DateTime, ClientSession};
use reqwest::Client;
use utu_bridge_types::{
    bitcoin::{BitcoinAddress, BitcoinRuneId, BitcoinTxId},
    starknet::StarknetAddress,
};

use crate::{
    models::{
        claim::FordefiDepositData,
        monitor::{FordefiId, FordefiTransaction, TransactionType},
        output::OrdOutputResult,
    },
    state::{database::DatabaseExt, AppState},
    utils::{
        calldata::get_transaction_struct_felt,
        fordefi::send_fordefi_request,
        runes::get_supported_runes_vec,
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
    static ref FORDEFI_DEPOSIT_VAULT_ID: String = env::var("FORDEFI_DEPOSIT_VAULT_ID").expect("FORDEFI_DEPOSIT_VAULT_ID must be set");
}

pub async fn process_block(
    state: &Arc<AppState>,
    block_hash: BlockHash,
    block: Block,
    main_loop: bool,
    block_height: u64,
) -> Result<()> {
    let mut session = match state.db.client().start_session().await {
        Ok(session) => session,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "Database error: unable to start session".to_string()
            ));
        }
    };

    let (supported_runes, runes_mapping) = get_supported_runes_vec(state).await?;
    let mut tx_found = false;

    let log_prefix = if main_loop {
        format!("[{}]", block_height)
    } else {
        format!("[{}|process_block]", block_height)
    };

    state.logger.info(format!(
        "[{}] Processing {} transactions",
        log_prefix,
        block.txdata.len()
    ));

    // parse to all the outputs, and check the ones that concerns us
    for (tx_index, tx) in block.txdata.iter().enumerate() {
        // Log progress every 100 transactions
        if tx_index % 100 == 0 {
            let percentage = (tx_index * 100) / block.txdata.len();
            state.logger.info(format!(
                "[{}] Progress: {}%, processed {} out of {} transactions",
                log_prefix,
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
                                        .was_submitted(&mut session, txid.to_string(), output_index)
                                        .await?
                                    {
                                        continue;
                                    }

                                    state.logger.info(format!(
                                        "[{}] Processing output {}:{} with supported runes: [{}]",
                                        log_prefix,
                                        txid,
                                        output_index,
                                        ord_data
                                            .runes
                                            .keys()
                                            .cloned()
                                            .collect::<Vec<String>>()
                                            .join(", ")
                                    ));

                                    if let Err(e) = process_deposit_transaction(
                                        state,
                                        &mut session,
                                        rune_spaced_name,
                                        rune_data.amount,
                                        txid.to_string(),
                                        output_index,
                                        &starknet_addr,
                                        &block_hash,
                                        &runes_mapping,
                                    )
                                    .await
                                    {
                                        state.logger.warning(format!(
                                        "Failed to process deposit transaction {}:{} at block height {} with error: {:?}",
                                        txid, output_index, block_height, e
                                    ));
                                    } else {
                                        tx_found = true;
                                    }
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    state.logger.warning(format!(
                        "Failed to get ord data for txid: {} and output_index: {} at block height {} with error: {:?}",
                        txid, output_index, block_height, err
                    ));
                }
            }
        }
    }

    state.logger.info(format!(
        "[{}] Completed processing all {} transactions",
        log_prefix,
        block.txdata.len()
    ));

    state
        .logger
        .info(format!("[{}] Completed processing block", log_prefix));

    if main_loop || tx_found {
        Ok(())
    } else {
        Err(anyhow::anyhow!(format!(
            "Unable to find any matching deposits in block: {}",
            block_height
        )))
    }
}

/// Processes a valid deposit transaction.
#[allow(clippy::too_many_arguments)]
pub async fn process_deposit_transaction(
    state: &Arc<AppState>,
    session: &mut ClientSession,
    rune_name: String,
    amount: u128,
    txid: String,
    vout: usize,
    starknet_addr: &StarknetAddress,
    block_hash: &BlockHash,
    runes_mapping: &HashMap<String, (BitcoinRuneId, u32)>,
) -> Result<()> {
    // Compute hash_value needed for fordefi signature
    let (hashed_value, rune_id_block_felt, rune_id_tx_felt, amount_u256) = if let Ok(hashed_value) =
        compute_hashed_value(
            runes_mapping,
            rune_name.clone(),
            amount,
            &txid,
            starknet_addr,
        ) {
        hashed_value
    } else {
        return Err(anyhow::anyhow!("Failed to compute hashed value"));
    };

    // Retrieve the complete transaction from bitcoin RPC
    // We need it to build the starknet transaction.
    match fetch_bitcoin_transaction_info(state, &txid, block_hash) {
        Ok(tx_info) => {
            let transaction_struct = get_transaction_struct_felt(&state.bitcoin_provider, tx_info);

            // we send the deposit request to fordefi
            let deposit_data = FordefiDepositData {
                rune_id_block: rune_id_block_felt,
                rune_id_tx: rune_id_tx_felt,
                amount: amount_u256,
                hashed_value,
                tx_id: txid.clone(),
                tx_vout: vout,
                transaction_struct,
                rune_contract: compute_rune_contract(rune_id_block_felt, rune_id_tx_felt),
                starknet_addr: starknet_addr.to_string(),
                vault_id: FORDEFI_DEPOSIT_VAULT_ID.clone(),
            };

            match send_fordefi_request(deposit_data).await {
                Ok(fordefi_id) => {
                    state
                        .logger
                        .debug(format!("Processed with Fordefi tx-id: {}", fordefi_id));
                    // store the fordefi_id in the database
                    let fordefi_tx = FordefiTransaction {
                        btc_txid: BitcoinTxId::new(&txid).unwrap(),
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
                        txid, vout, err
                    ));
                }
            }
        }
        Err(err) => {
            state.logger.warning(format!(
                "Failed to retrieve transaction data for txid: {}:{} with error: {:?}",
                txid, vout, err
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
    let url = format!("https://{}/output/{}:{}", *ORD_NODE_URL, txid, vout);

    let response = HTTP_CLIENT
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to query ord API for {}:{}, status: {}",
            txid,
            vout,
            response.status()
        ));
    }

    let ord_output: OrdOutputResult = response.json().await?;
    Ok(ord_output)
}
