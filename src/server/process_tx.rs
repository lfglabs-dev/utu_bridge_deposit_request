use anyhow::Result;
use bitcoincore_rpc::RpcApi;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use utu_bridge_types::bitcoin::BitcoinAddress;

use crate::models::output::OutputToProcess;
use crate::process_block::{get_ord_data, process_output};
use crate::server::responses::{ApiResponse, Status};
use crate::state::database::DatabaseExt;
use crate::state::AppState;
use crate::utils::general::is_valid_tx_id;
use crate::utils::runes::get_supported_runes_vec;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use axum_auto_routes::route;
use bitcoin::{Address, BlockHash, Network, Txid};
use mongodb::bson::doc;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessTxQuery {
    tx_id: String,
}

lazy_static::lazy_static! {
    static ref HTTP_CLIENT: Client = Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .build()
        .expect("Failed to create HTTP client");
}

#[route(post, "/process_tx")]
pub async fn process_tx_query(
    State(state): State<Arc<AppState>>,
    body: Json<ProcessTxQuery>,
) -> impl IntoResponse {
    if let Err(err) = process_tx(&state, body.tx_id.clone()).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::new(
                Status::InternalServerError,
                format!(
                    "Error while processing transaction {:?}: {:?}",
                    body.tx_id, err
                ),
            )),
        );
    }

    (
        StatusCode::ACCEPTED,
        Json(ApiResponse::new(Status::Success, true)),
    )
}

async fn process_tx(state: &Arc<AppState>, tx_id: String) -> Result<()> {
    let mut session = match state.db.client().start_session().await {
        Ok(session) => session,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "Database error: unable to start session".to_string()
            ));
        }
    };

    // Validate transaction ID format
    if !is_valid_tx_id(&tx_id) {
        return Err(anyhow::anyhow!(
            "Invalid transaction ID format. Must contain only hex characters (0-9, a-f, A-F)."
        ));
    }

    let (supported_runes, runes_mapping) = get_supported_runes_vec(state).await?;
    let mut tx_found = false;

    let txid = Txid::from_str(&tx_id)?;
    let tx = match state.bitcoin_provider.get_raw_transaction(&txid, None) {
        Ok(tx) => tx,
        Err(e) => return Err(anyhow::anyhow!("Error while fetching transaction: {:?}", e)),
    };

    let block_hash = get_block_hash(state, tx_id.clone()).await?;

    for (output_index, vout) in tx.output.iter().enumerate() {
        let ord_data = get_ord_data(txid.to_string(), output_index).await?;
        for (rune_spaced_name, rune_data) in ord_data.runes.clone() {
            if supported_runes.contains(&rune_spaced_name) {
                // Check if the output is one of our deposit addresses
                if let Ok(receiver_address) =
                    Address::from_script(&vout.script_pubkey, Network::Bitcoin)
                {
                    let btc_receiver_address =
                        BitcoinAddress::new(&receiver_address.to_string(), Network::Bitcoin)?;

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
                            state.logger.info(format!(
                                "[process_tx] Transaction already submitted: {}:{}. Skipping...",
                                txid, output_index
                            ));
                            continue;
                        }

                        state.logger.info(format!(
                            "[process_tx] Processing output {}:{} with supported runes: [{}]",
                            txid,
                            output_index,
                            ord_data
                                .runes
                                .keys()
                                .cloned()
                                .collect::<Vec<String>>()
                                .join(", ")
                        ));

                        if let Err(e) = process_output(
                            state,
                            &mut session,
                            OutputToProcess {
                                rune_spaced_name,
                                rune_data,
                                txid: txid.to_string(),
                                output_index,
                                starknet_addr,
                            },
                            block_hash,
                            &runes_mapping,
                        )
                        .await
                        {
                            state.logger.warning(format!(
                                "[process_tx] Failed to process deposit transaction {}:{} with error: {:?}",
                                txid, output_index, e
                            ));
                        } else {
                            tx_found = true;
                            state.logger.info(format!(
                                "[process_tx] Processed deposit transaction for tx_id: {}",
                                tx_id
                            ));
                        }
                    }
                }
            }
        }
    }

    if !tx_found {
        return Err(anyhow::anyhow!("Unable to find a matching deposit."));
    }

    Ok(())
}

async fn get_block_hash(state: &Arc<AppState>, tx_id: String) -> Result<BlockHash> {
    let txid = Txid::from_str(&tx_id)?;
    let tx = state
        .bitcoin_provider
        .get_raw_transaction_info(&txid, None)?;

    let block_hash = tx.blockhash.ok_or(anyhow::anyhow!("No block hash found"))?;

    Ok(block_hash)
}
