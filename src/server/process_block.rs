use std::str::FromStr;
use std::sync::Arc;

use crate::models::blocks::BlockWithTransactions;
use crate::process_block::process_block;
use crate::server::responses::{ApiResponse, Status};
use crate::state::AppState;
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
        .call::<BlockWithTransactions>("getblock", &[block_hash_value, 2.into()])
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

    if let Err(e) = process_block(&state, block_hash, block, false, height).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::new(
                Status::InternalServerError,
                format!("Error while processing block: {:?}", e),
            )),
        );
    }

    (
        StatusCode::ACCEPTED,
        Json(ApiResponse::new(Status::Success, true)),
    )
}
