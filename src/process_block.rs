use std::{env, str::FromStr, sync::Arc, time::Duration};

use anyhow::Result;
use bitcoin::{BlockHash, Txid};
use bitcoincore_rpc::RpcApi;
use reqwest::Client;
use serde_json::json;

use crate::{
    models::{
        claim::{ClaimCalldata, ClaimDepositDataRes},
        hiro::{BlockActivity, Operation, RuneActivityForAddress},
    },
    state::{database::DatabaseExt, transactions::TransactionBuilderStateTrait, AppState},
    utils::calldata::{get_transaction_struct_felt, hex_to_hash_rev},
};

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

pub async fn process_block(state: &Arc<AppState>, block_hash: BlockHash) -> Result<()> {
    let mut session = match state.db.client().start_session().await {
        Ok(session) => session,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "Database error: unable to start session".to_string()
            ));
        }
    };
    if let Err(err) = session.start_transaction().await {
        return Err(anyhow::anyhow!("Database error: {:?}", err));
    };

    let supported_runes_array = state.db.get_supported_runes(&mut session).await?;
    let supported_runes = supported_runes_array
        .iter()
        .map(|rune| rune.id.clone())
        .collect::<Vec<String>>();

    let mut offset = 0;
    let mut total = 0;
    loop {
        let url = format!(
            "{}/runes/v1/blocks/{}/activity?offset={}&limit=60",
            *HIRO_API_URL, block_hash, offset
        );
        let res = HTTP_CLIENT
            .get(url)
            .header("x-api-key", HIRO_API_KEY.clone())
            .send()
            .await?;

        if res.status().is_success() {
            let block_activity = res.json::<BlockActivity>().await?;
            total = block_activity.total;

            for tx in block_activity.results {
                if tx.operation == Operation::Receive
                    && tx.address.is_some()
                    && supported_runes.contains(&tx.rune.id)
                {
                    // In results of type Receive we don't have the receiver_address, only the sender_address
                    // We fetch the transaction details based on tx_id to get the receiver_address
                    let receiver_address = if let Ok(receiver_address) = get_receiver_addr(
                        tx.location.tx_id.clone(),
                        tx.address.clone().unwrap(),
                        tx.rune.id.clone(),
                    )
                    .await
                    {
                        receiver_address
                    } else {
                        state.logger.warning(format!(
                            "Failed to get receiver address for tx_id: {}",
                            tx.address.clone().unwrap()
                        ));
                        continue;
                    };

                    if let Ok(starknet_addr) = state
                        .db
                        .is_deposit_addr(&mut session, receiver_address.clone())
                        .await
                    {
                        // Retrieve claim data from UTU API
                        let url = format!("{}/claim_deposit_data", *UTU_API_URL,);
                        let client = Client::new();
                        let payload = json!({
                            "starknet_addr": starknet_addr,
                            "bitcoin_deposit_addr": receiver_address,
                            "tx_id": tx.location.tx_id,
                            "tx_vout": tx.location.vout,
                        });
                        let claim_res = client.post(&url).json(&payload).send().await?;

                        if claim_res.status().is_success() {
                            let claim_data = claim_res.json::<ClaimDepositDataRes>().await?;

                            // Retrieve the complete transaction from bitcoin RPC
                            match state.bitcoin_provider.get_raw_transaction_info(
                                &Txid::from_str(&tx.location.tx_id).unwrap(),
                                Some(&block_hash),
                            ) {
                                Ok(tx_info) => {
                                    let transaction_struct = get_transaction_struct_felt(
                                        &state.bitcoin_provider,
                                        tx_info,
                                    );
                                    let tx_id = match Txid::from_str(&claim_data.data.tx_id) {
                                        Ok(tx_id) => Some(tx_id),
                                        Err(_) => None,
                                    };
                                    state
                                        .transactions
                                        .add_transaction(ClaimCalldata {
                                            rune_id: claim_data.data.rune_id,
                                            amount: claim_data.data.amount,
                                            target_addr: claim_data.data.target_addr,
                                            sig: claim_data.data.sig,
                                            tx_id: hex_to_hash_rev(tx_id),
                                            tx_id_str: claim_data.data.tx_id,
                                            transaction_struct,
                                        })
                                        .await;
                                }
                                Err(err) => {
                                    state.logger.warning(format!("Failed to retrieve transaction data for tx_id: {} with error: {:?}", tx.location.tx_id, err));
                                }
                            }
                        } else {
                            state.logger.warning(format!(
                                "Failed to retrieve claim data for deposit address: {} with error: {:?}",
                                receiver_address, claim_res.text().await
                            ));
                        }
                    }
                }
            }
        }

        // we fetch 60 txs at a time and a block can have more so
        // we continue fetching until we analyze all txs
        offset += 1;
        if total <= offset * 60 {
            break;
        }
    }

    state
        .logger
        .info(format!("Completed processing block: {}", block_hash));

    if let Err(err) = session.commit_transaction().await {
        return Err(anyhow::anyhow!("Database error: {:?}", err));
    };

    Ok(())
}

async fn get_receiver_addr(txid: String, sender_addr: String, rune_id: String) -> Result<String> {
    let mut offset = 0;
    let mut total = 0;

    loop {
        // We fetch the activity for the sender address to retrieve activities of type Send
        // that matches our transaction
        let url = format!(
            "{}/runes/v1/etchings/{}/activity/{}?offset={}&limit=60",
            *HIRO_API_URL, rune_id, sender_addr, offset
        );

        let res = HTTP_CLIENT
            .get(url)
            .header("x-api-key", HIRO_API_KEY.clone())
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to get activity for rune: {} and address: {}",
                rune_id,
                sender_addr
            ));
        }

        let account_activity = res.json::<RuneActivityForAddress>().await?;
        total = account_activity.total;

        for activity in account_activity.results {
            if activity.operation == Operation::Send
                && activity.address.is_some()
                && activity.receiver_address.is_some()
                && activity.location.tx_id == txid
            {
                let addr = activity.clone().address.unwrap();
                if addr == sender_addr {
                    return Ok(activity.clone().receiver_address.unwrap());
                }
            }
        }

        // we fetch 60 txs at a time and a block can have more so
        // we continue fetching until we analyze all txs
        offset += 1;
        if total <= offset * 60 {
            break;
        }
    }

    Err(anyhow::anyhow!(
        "Failed to find receiver address for rune: {} and address: {}",
        rune_id,
        sender_addr
    ))
}
