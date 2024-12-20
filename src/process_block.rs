use std::{env, str::FromStr, sync::Arc};

use anyhow::Result;
use bitcoin::{BlockHash, Txid};
use bitcoincore_rpc::RpcApi;
use reqwest::Client;
use serde_json::json;

use crate::{
    models::{
        claim::{ClaimCalldata, ClaimDepositDataRes},
        hiro::{BlockActivity, Operation},
    },
    state::{database::DatabaseExt, transactions::TransactionBuilderStateTrait, AppState},
    utils::calldata::{get_transaction_struct_felt, hex_to_hash_rev},
};

lazy_static::lazy_static! {
    static ref HIRO_API_URL: String = env::var("HIRO_API_URL").expect("HIRO_API_URL must be set");
    static ref HIRO_API_KEY: String = env::var("HIRO_API_KEY").expect("HIRO_API_KEY must be set");
    static ref UTU_API_URL: String = env::var("UTU_API_URL").expect("UTU_API_URL must be set");
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
        let client = Client::new();
        let res = client
            .get(url)
            .header("x-api-key", HIRO_API_KEY.clone())
            .send()
            .await?;

        if res.status().is_success() {
            let block_activity = res.json::<BlockActivity>().await?;
            total = block_activity.total;

            for tx in block_activity.results {
                if tx.operation == Operation::Send
                    && tx.receiver_address.is_some()
                    && supported_runes.contains(&tx.rune.id)
                {
                    let receiver_address = tx.receiver_address.clone().unwrap();
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
