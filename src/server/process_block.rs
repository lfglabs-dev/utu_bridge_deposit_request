use std::str::FromStr;
use std::sync::Arc;

use crate::models::blocks::BlockWithTransactions;
use crate::process_block::{self, process_output, wait_for_block_confirmation};
use crate::server::responses::{ApiResponse, Status};
use crate::state::AppState;
use crate::utils::runes::get_supported_runes_vec;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use axum_auto_routes::route;
use bitcoin::BlockHash;
use bitcoincore_rpc::RpcApi;
use mongodb::bson::doc;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessBlockQuery {
    block_hash: String,
}

#[route(post, "/process_block")]
pub async fn process_block_query(
    State(state): State<Arc<AppState>>,
    body: Json<ProcessBlockQuery>,
) -> impl IntoResponse {
    let mut session = match state.db.client().start_session().await {
        Ok(session) => session,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::new(
                    Status::InternalServerError,
                    format!(
                        "Database error: unable to start session when processing block {:?}",
                        e
                    ),
                )),
            );
        }
    };

    let (supported_runes, runes_mapping) = match get_supported_runes_vec(&state).await {
        Ok(runes) => runes,
        Err(e) => {
            state.logger.warning(format!(
                "[{}] Failed to get supported runes: {}",
                body.block_hash, e
            ));
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::new(
                    Status::InternalServerError,
                    format!(
                        "Failed to get supported runes in process_block endpoint: {:?}",
                        e
                    ),
                )),
            );
        }
    };

    let block_hash = if let Ok(hash) = BlockHash::from_str(&body.block_hash) {
        hash
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::new(Status::BadRequest, "Invalid block hash")),
        );
    };

    let block = match state.bitcoin_provider.get_block(&block_hash) {
        Ok(block) => block,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::new(
                    Status::InternalServerError,
                    format!("Error while fetching block height: {:?}", e),
                )),
            )
        }
    };

    let block_hash_value = match serde_json::to_value(block_hash) {
        Ok(value) => value,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::new(
                    Status::InternalServerError,
                    format!("Error while fetching block height: {:?}", e),
                )),
            );
        }
    };
    let height = match state
        .bitcoin_provider
        .call::<BlockWithTransactions>("getblock", &[block_hash_value.clone(), 2.into()])
    {
        Ok(block) => block.height,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::new(
                    Status::InternalServerError,
                    format!("Error while fetching block height: {:?}", e),
                )),
            );
        }
    };

    let outputs_to_process = match process_block::parse_block(
        &state,
        &mut session,
        height,
        block.clone(),
        supported_runes,
    )
    .await
    {
        Ok(outputs) => outputs,
        Err(e) => {
            state
                .logger
                .warning(format!("[{}] Failed to parse block: {}", block_hash, e));
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::new(
                    Status::InternalServerError,
                    format!(
                        "Failed to parse block {} in process_block endpoint: {:?}",
                        height, e
                    ),
                )),
            );
        }
    };

    // Waiting for the block to be confirmed
    if wait_for_block_confirmation(&state, block_hash_value)
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::new(
                Status::InternalServerError,
                format!(
                    "Block {} was not integrated (confirmations = -1), stopping task",
                    height
                ),
            )),
        );
    }

    // process the outputs
    for output in outputs_to_process {
        if let Err(e) =
            process_output(&state, &mut session, output, block_hash, &runes_mapping).await
        {
            state.logger.severe(format!("[{}] {}", height, e));
        }
    }

    (
        StatusCode::ACCEPTED,
        Json(ApiResponse::new(Status::Success, true)),
    )
}
