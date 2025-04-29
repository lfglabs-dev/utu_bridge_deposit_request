use anyhow::Result;
use mongodb::ClientSession;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use utu_bridge_types::bitcoin::BitcoinAddress;

use crate::models::hiro::BlockActivity;
use crate::process_block::{is_valid_receive_operation, process_deposit_transaction};
use crate::server::responses::{ApiResponse, Status};
use crate::state::database::DatabaseExt;
use crate::state::AppState;
use crate::utils::general::is_valid_tx_id;
use crate::utils::runes::get_supported_runes_vec;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use axum_auto_routes::route;
use bitcoin::{BlockHash, Network};
use mongodb::bson::doc;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessTxQuery {
    tx_id: String,
}

lazy_static::lazy_static! {
    static ref HIRO_API_URL: String = env::var("HIRO_API_URL").expect("HIRO_API_URL must be set");
    static ref HIRO_API_KEY: String = env::var("HIRO_API_KEY").expect("HIRO_API_KEY must be set");
    static ref HIRO_TIMEOUT_MS: u64 = env::var("HIRO_TIMEOUT_MS").expect("HIRO_TIMEOUT_MS must be set").parse::<u64>().expect("HIRO_TIMEOUT_MS must be a valid u64");
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
    let mut session = match state.db.client().start_session().await {
        Ok(session) => session,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::new(
                    Status::InternalServerError,
                    "Database error: unable to start session",
                )),
            );
        }
    };
    if let Err(err) = session.start_transaction().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::new(
                Status::InternalServerError,
                format!("Database error: {:?}", err),
            )),
        );
    };

    if let Err(err) = process_tx(&state, &mut session, body.tx_id.clone()).await {
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

async fn process_tx(
    state: &Arc<AppState>,
    session: &mut ClientSession,
    tx_id: String,
) -> Result<()> {
    // Validate transaction ID format
    if !is_valid_tx_id(&tx_id) {
        return Err(anyhow::anyhow!(
            "Invalid transaction ID format. Must contain only hex characters (0-9, a-f, A-F)."
        ));
    }

    let (supported_runes, runes_mapping) = get_supported_runes_vec(state).await?;

    // Fetch transaction details and parse all activities
    let mut offset = 0;
    loop {
        let url = format!(
            "{}/runes/v1/transactions/{}/activity?offset={}&limit=60",
            *HIRO_API_URL, tx_id, offset
        );
        let res = HTTP_CLIENT
            .get(url)
            .header("x-api-key", HIRO_API_KEY.clone())
            .send()
            .await?;

        if !res.status().is_success() {
            state
                .logger
                .warning(format!("Failed to get activity for txid: {}", tx_id));
            continue;
        }

        let tx_activity = res.json::<BlockActivity>().await?;

        for tx in tx_activity.results {
            if is_valid_receive_operation(&tx, &supported_runes) {
                let receiver_address = tx.address.clone().unwrap();
                let receiver_address = BitcoinAddress::new(&receiver_address, Network::Bitcoin)?;

                // Check if the received_address is part of our deposit addresses
                if let Ok(starknet_addr) = state
                    .db
                    .is_deposit_addr(session, &state.logger, receiver_address.clone())
                    .await
                {
                    let block_hash = if let Ok(hash) = BlockHash::from_str(&tx.location.block_hash)
                    {
                        hash
                    } else {
                        return Err(anyhow::anyhow!("Invalid block hash"));
                    };
                    // we process the deposit transaction and add it to queue.
                    if let Err(e) = process_deposit_transaction(
                        state,
                        &tx,
                        &starknet_addr,
                        &block_hash,
                        &runes_mapping,
                    )
                    .await
                    {
                        state.logger.warning(format!(
                            "Failed to process deposit transaction for tx_id: {}: {:?}",
                            tx.location.tx_id, e
                        ));
                        return Err(e);
                    } else {
                        state.logger.info(format!(
                            "Processed deposit transaction for tx_id: {}",
                            tx.location.tx_id
                        ));
                        return Ok(());
                    }
                }
            }
        }

        // we fetch 60 activities at a time and a tx could have more so
        // we continue fetching until we analyze all activities in tx
        offset += 60;
        if offset >= tx_activity.total {
            break;
        }

        // we sleep for HIRO_TIMEOUT_MS to avoid rate limit
        sleep(Duration::from_millis(*HIRO_TIMEOUT_MS)).await;
    }

    Err(anyhow::anyhow!(
        "Failed to process transaction. Unable to find a matching deposit."
    ))
}
