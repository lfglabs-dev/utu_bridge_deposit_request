use std::env;

use starknet::core::types::Felt;
use tokio::sync::RwLock;

use crate::{models::claim::ClaimCalldata, utils::general::get_current_timestamp};

use super::TransactionBuilderState;

#[derive(Debug, Clone, PartialEq)]
pub enum TxStatus {
    Success,
    Failed,
    Reverted,
}

pub trait TransactionBuilderStateTrait {
    fn init(nonce: Felt) -> Self;
    async fn get_tx_count(&self) -> usize;
    async fn add_transaction(&self, tx: ClaimCalldata);
    async fn empty_transactions_state(&self, amount: usize) -> Vec<ClaimCalldata>;
}

impl TransactionBuilderStateTrait for TransactionBuilderState {
    fn init(nonce: Felt) -> Self {
        let last_sent_timestamp_ms = get_current_timestamp();
        let max_wait_time_ms = env::var("MAX_WAIT_TIME_MS")
            .expect("MAX_WAIT_TIME_MS must be set")
            .parse::<u64>()
            .expect("Unable to convert MAX_WAIT_TIME_MS to u64");
        let min_wait_time_sec = env::var("MIN_WAIT_TIME_MS")
            .expect("MIN_WAIT_TIME_MS must be set")
            .parse::<u64>()
            .expect("Unable to convert MIN_WAIT_TIME_MS to u64");
        let max_queue_length = env::var("MAX_QUEUE_LENGTH")
            .expect("MAX_QUEUE_LENGTH must be set")
            .parse::<usize>()
            .expect("Unable to convert MAX_QUEUE_LENGTH to usize");

        TransactionBuilderState {
            max_queue_length,
            max_wait_time_ms,
            min_wait_time_sec,
            last_sent_timestamp_ms: RwLock::new(last_sent_timestamp_ms),
            nonce: RwLock::new(nonce),
            data: RwLock::new(Vec::new()),
        }
    }

    async fn get_tx_count(&self) -> usize {
        self.with_transactions_read(|txs| txs.len()).await
    }

    async fn add_transaction(&self, tx: ClaimCalldata) {
        self.with_transactions(|data| {
            data.push(tx);
        })
        .await;
    }

    async fn empty_transactions_state(&self, amount: usize) -> Vec<ClaimCalldata> {
        let mut res: Vec<ClaimCalldata> = Vec::new();

        self.with_transactions(|data| {
            for _ in 0..amount {
                if let Some(tx) = data.pop() {
                    res.push(tx);
                }
            }
        })
        .await;

        res
    }
}
