use anyhow::Result;
use mongodb::ClientSession;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::models::hiro::BlockActivity;
use crate::process_block::{is_valid_receive_operation, process_deposit_transaction};
use crate::server::responses::{ApiResponse, Status};
use crate::state::database::DatabaseExt;
use crate::state::AppState;
use crate::utils::runes::get_supported_runes_vec;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use axum_auto_routes::route;
use bitcoin::BlockHash;
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
    static ref UTU_API_URL: String = env::var("UTU_API_URL").expect("UTU_API_URL must be set");
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
    let supported_runes = get_supported_runes_vec(state).await?;

    // Fetch transaction details and parse all activities
    let mut offset = 0;
    let mut total = 0;
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
        total += tx_activity.total;

        for tx in tx_activity.results {
            if is_valid_receive_operation(&tx, &supported_runes) {
                let receiver_address = tx.address.clone().unwrap();

                // Check if the received_address is part of our deposit addresses
                if let Ok(starknet_addr) = state
                    .db
                    .is_deposit_addr(session, receiver_address.clone())
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

        // we fetch 60 activities at a time and a tx could have more so
        // we continue fetching until we analyze all activities in tx
        offset += 1;
        if total <= offset * 60 {
            break;
        }
    }

    Ok(())
}
