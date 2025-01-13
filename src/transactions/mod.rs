use std::{sync::Arc, time::Duration};

use anyhow::Result;
use starknet::{
    accounts::Account,
    core::types::{Call, Felt, TransactionExecutionStatus, TransactionStatus},
    providers::Provider,
};
use tokio::time::sleep;

use crate::{
    models::claim::ClaimCalldata,
    state::{transactions::TxStatus, AppState},
    utils::{
        blacklist::blacklist_deposits,
        general::{get_current_timestamp, to_hex},
        starknet::prepare_multicall,
    },
};

pub async fn build_and_run_multicall(state: &Arc<AppState>, transactions: Vec<ClaimCalldata>) {
    // Prepare the multicall
    let (execute_calls, tx_ids) = prepare_multicall(state, transactions).await;

    if execute_calls.is_empty() {
        state
            .logger
            .info("No valid transactions to execute, closing process".to_string());
        return;
    }

    // Execute the multicall
    let process_nonce = state.transactions.with_nonce_read(|n| *n).await;
    match execute_multicall(state, execute_calls.clone(), process_nonce).await {
        Ok(tx_hash) => {
            state.logger.info(format!(
                "Process {}: Transaction sent with hash {:?}",
                process_nonce,
                to_hex(&tx_hash)
            ));
            let status = get_transaction_status(state, tx_hash).await;

            // We check the status
            if status == TxStatus::Success {
                state.logger.info(format!(
                    "Transaction {:?} succeeded in process with nonce {}",
                    to_hex(&tx_hash),
                    process_nonce
                ));
                if let Err(e) = blacklist_deposits(state, tx_ids).await {
                    state.logger.severe(format!(
                        "Error while blacklisting deposits for process {}: {:?}",
                        process_nonce, e
                    ));
                }
            } else {
                state.logger.severe(format!(
                    "Transaction {:?} failed in process with nonce {}",
                    to_hex(&tx_hash),
                    process_nonce
                ));
            }
        }
        Err(e) => {
            state.logger.severe(format!(
                "Closing process {}: Error while executing multicall: {:?}",
                process_nonce, e
            ));
        }
    }
}

pub async fn execute_multicall(
    state: &Arc<AppState>,
    calls: Vec<Call>,
    nonce: Felt,
) -> Result<Felt> {
    // We ensure transaction can be sent
    state
        .logger
        .info(format!("Process {} waiting to send its tx", nonce));
    let is_ready = can_send_tx(state).await;
    if !is_ready {
        return Err(anyhow::anyhow!(
            "Process {}: invariant in execute_multicall, it should receive a ready tx",
            nonce
        ));
    }
    state
        .logger
        .info(format!("Process {} is ready to send its tx", nonce));

    _execute_multicall_common(state, calls, nonce).await
}

async fn can_send_tx(state: &Arc<AppState>) -> bool {
    loop {
        // We check last_sent_timestamp_ms to ensure we are not sending too many transactions at once
        let last_sent_timestamp_ms = state.transactions.with_last_sent(|t| *t).await;
        let delta = get_current_timestamp() - last_sent_timestamp_ms;

        if delta < state.transactions.min_wait_time_sec {
            sleep(Duration::from_secs(1)).await;
        } else {
            return true;
        }
    }
}

pub async fn _execute_multicall_common(
    state: &Arc<AppState>,
    calls: Vec<Call>,
    nonce: Felt,
) -> Result<Felt> {
    let execution = state.starknet_account.execute_v1(calls);
    match execution.estimate_fee().await {
        Ok(_) => match execution
            .nonce(nonce)
            // harcode max fee to 0.0040 ETH
            .max_fee(Felt::from(4000000000000000_u64))
            .send()
            .await
        {
            Ok(tx_result) => {
                // We update the locks and drop them right away
                state.transactions.with_nonce(|n| *n += Felt::ONE).await;
                state
                    .transactions
                    .with_last_sent(|t| *t = get_current_timestamp())
                    .await;

                Ok(tx_result.transaction_hash)
            }
            Err(e) => {
                let error_message = format!(
                    "Process {}: An error occurred while executing multicall: {:?}",
                    nonce, e
                );
                Err(anyhow::anyhow!(error_message))
            }
        },
        Err(e) => {
            let error_message = format!(
                "Process {}: An error occurred while simulating multicall: {:?}",
                nonce, e
            );

            Err(anyhow::anyhow!(error_message))
        }
    }
}

pub async fn get_transaction_status(state: &Arc<AppState>, tx_hash: Felt) -> TxStatus {
    let max_attempts = 50;
    let mut attempts = 0;
    let delay = Duration::from_secs(10);

    // We wait 10 seconds before starting to check the status
    // otherwise we might get a TransactionHashNotFound error
    sleep(delay).await;

    while attempts < max_attempts {
        match state
            .starknet_provider
            .get_transaction_status(tx_hash)
            .await
        {
            Ok(tx_status) => match tx_status {
                TransactionStatus::Received => {
                    attempts = 0; // Reset attempts if we are getting valid responses
                }
                TransactionStatus::Rejected => return TxStatus::Failed,
                TransactionStatus::AcceptedOnL2(execution_status)
                | TransactionStatus::AcceptedOnL1(execution_status) => {
                    return match execution_status {
                        TransactionExecutionStatus::Succeeded => TxStatus::Success,
                        TransactionExecutionStatus::Reverted => TxStatus::Reverted,
                    };
                }
            },
            Err(e) => {
                state.logger.warning(format!(
                    "Error while getting transaction status for {} with error : {:?}, waiting 10 seconds before retrying.",
                    to_hex(&tx_hash),
                    e
                ));
                // we could have an error of type TransactionHashNotFound, so we should retry
                // we still add a limit of attempts in case something else happens
                attempts += 1;
                sleep(delay).await;
                continue;
            }
        }
    }

    TxStatus::Failed
}
