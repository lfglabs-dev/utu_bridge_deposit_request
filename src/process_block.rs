use std::{env, sync::Arc};

use anyhow::Result;
use bitcoin::BlockHash;
use reqwest::Client;
use serde_json::json;

use crate::{
    models::{
        claim::ClaimDepositDataRes,
        hiro::{BlockActivity, Operation},
    },
    state::{database::DatabaseExt, transactions::TransactionBuilderStateTrait, AppState},
};

lazy_static::lazy_static! {
    static ref HIRO_API_URL: String = env::var("HIRO_API_URL").expect("HIRO_API_URL must be set");
    static ref HIRO_API_KEY: String = env::var("HIRO_API_KEY").expect("HIRO_API_KEY must be set");
    static ref UTU_API_URL: String = env::var("UTU_API_URL").expect("UTU_API_URL must be set");
}

pub async fn process_block(state: &Arc<AppState>, _block_hash: BlockHash) -> Result<()> {
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

    let mut offset = 0;
    let mut total = 0;
    loop {
        let url = format!(
            "{}/runes/v1/blocks/{}/activity?offset={}&limit=60",
            *HIRO_API_URL,
            // block_hash,
            "871055", // testing value
            offset
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
                if tx.operation == Operation::Send && tx.receiver_address.is_some() {
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
                            "tx_data": tx
                        });
                        let claim_res = client.post(&url).json(&payload).send().await?;

                        if claim_res.status().is_success() {
                            let claim_data = claim_res.json::<ClaimDepositDataRes>().await?;
                            state.transactions.add_transaction(claim_data.data).await;
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

        // we fetch 60 txs at a time and a block can have more so we continue fetching until we analyze all txs
        offset += 1;
        //todo: uncomment after testing
        // if total <= offset * 60 {
        //     break;
        // }

        // todo: remove this, and uncomment above, it's just for testing as api doesn't work on testnet
        if offset == 1 {
            break;
        }
    }

    if let Err(err) = session.commit_transaction().await {
        return Err(anyhow::anyhow!("Database error: {:?}", err));
    };

    Ok(())
}
