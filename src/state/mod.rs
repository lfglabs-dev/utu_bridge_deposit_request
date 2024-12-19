use bitcoin::BlockHash;
use bitcoincore_rpc::Client;
use mongodb::Database;
use starknet::{
    accounts::SingleOwnerAccount,
    core::types::Felt,
    providers::{jsonrpc::HttpTransport, JsonRpcClient},
    signers::LocalWallet,
};
use thiserror::Error;

use axum::{body::Body, Router};
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};

use crate::{logger::Logger, models::claim::ClaimCalldata};

pub mod blocks;
pub mod database;
pub mod init;
pub mod transactions;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("No result found for the specified query")]
    NotFound,
    #[error("Database query failed")]
    QueryFailed(#[from] mongodb::error::Error),
    #[error("Data deserialization failed")]
    DeserializationFailed(#[from] mongodb::bson::de::Error),
    #[error("Other error: {0}")]
    Other(String),
}

impl From<anyhow::Error> for DatabaseError {
    fn from(error: anyhow::Error) -> Self {
        DatabaseError::Other(error.to_string())
    }
}

pub struct AppState {
    pub logger: Logger,
    pub db: Database,
    pub bitcoin_provider: Client,
    pub starknet_provider: JsonRpcClient<HttpTransport>,
    pub starknet_account: SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    pub blocks: RwLock<BlocksState>,
    pub transactions: TransactionBuilderState,
    pub notifier: Notify,
}

pub struct BlocksState {
    hashes: Vec<BlockHash>,
}

pub struct TransactionBuilderState {
    pub max_queue_length: usize,
    pub max_wait_time_ms: u64,
    pub min_wait_time_sec: u64,
    pub last_sent_timestamp_ms: RwLock<u64>,
    pub nonce: RwLock<Felt>,
    pub data: RwLock<Vec<ClaimCalldata>>,
}

// required for axum_auto_routes
pub trait WithState: Send {
    fn to_router(self: Box<Self>, shared_state: Arc<AppState>) -> Router;

    fn box_clone(&self) -> Box<dyn WithState>;
}

impl WithState for Router<Arc<AppState>, Body> {
    fn to_router(self: Box<Self>, shared_state: Arc<AppState>) -> Router {
        self.with_state(shared_state)
    }

    fn box_clone(&self) -> Box<dyn WithState> {
        Box::new((*self).clone())
    }
}

impl Clone for Box<dyn WithState> {
    fn clone(&self) -> Box<dyn WithState> {
        self.box_clone()
    }
}

macro_rules! impl_with_lock {
    ($name:ident, $field:ident, $type:ty) => {
        pub async fn $name<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&mut $type) -> R,
        {
            let mut guard = self.$field.write().await;
            f(&mut guard)
        }

        paste::paste! {
            pub async fn [<$name _read>]<F, R>(&self, f: F) -> R
            where
                F: FnOnce(&$type) -> R,
            {
                let guard = self.$field.read().await;
                f(&guard)
            }
        }
    };
}

impl AppState {
    impl_with_lock!(with_blocks, blocks, BlocksState);
}

impl TransactionBuilderState {
    impl_with_lock!(with_last_sent, last_sent_timestamp_ms, u64);
    impl_with_lock!(with_nonce, nonce, Felt);
    impl_with_lock!(with_transactions, data, Vec<ClaimCalldata>);
}
