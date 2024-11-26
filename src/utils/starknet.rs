use std::{env, sync::Arc};

use anyhow::Result;
use reqwest::Url;
use starknet::{
    accounts::{Call, ConnectedAccount, SingleOwnerAccount},
    core::{
        types::{BlockId, BlockTag, FieldElement},
        utils::{get_udc_deployed_address, UdcUniqueness},
    },
    macros::selector,
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::{LocalWallet, SigningKey},
};

use crate::{models::claim::ClaimData, state::AppState};

use super::general::get_current_timestamp;

lazy_static::lazy_static! {
    static ref RUNE_BRIDGE_CONTRACT: FieldElement = FieldElement::from_hex_be(&env::var("RUNE_BRIDGE_CONTRACT").expect("RUNE_BRIDGE_CONTRACT must be set")).unwrap();
    static ref SAG_CLASS_HASH: FieldElement = FieldElement::from_hex_be(&env::var("SAG_CLASS_HASH").expect("SAG_CLASS_HASH must be set")).unwrap();
}

pub async fn get_account() -> SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet> {
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse(&env::var("STARKNET_RPC_URL").expect("STARKNET_RPC_URL must be set")).unwrap(),
    ));
    let chainid = provider.chain_id().await.unwrap();
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(
        FieldElement::from_hex_be(
            &env::var("ACCOUNT_PRIV_KEY").expect("ACCOUNT_PRIV_KEY must be set"),
        )
        .unwrap(),
    ));
    SingleOwnerAccount::new(
        provider,
        signer,
        FieldElement::from_hex_be(
            &env::var("ACCOUNT_ADDRESS").expect("ACCOUNT_ADDRESS must be set"),
        )
        .unwrap(),
        chainid,
        starknet::accounts::ExecutionEncoding::New,
    )
}

pub async fn prepare_multicall(
    state: &Arc<AppState>,
    transactions: Vec<ClaimData>,
) -> (Vec<Call>, Vec<String>) {
    let mut calls: Vec<Call> = Vec::new();
    let mut tx_ids: Vec<String> = Vec::new();

    for transaction in transactions {
        // ensure the rune contract is deployed
        let rune_contract = compute_rune_contract(transaction.rune_id);
        if is_deployed_on_starknet(state, rune_contract).await.is_ok() {
            calls.push(Call {
                to: *RUNE_BRIDGE_CONTRACT,
                selector: selector!("claim_runes"),
                calldata: vec![
                    transaction.rune_id,
                    transaction.amount.0,
                    transaction.amount.1,
                    transaction.target_addr.felt,
                ],
            });
            tx_ids.push(transaction.tx_id);
        }
    }

    (calls, tx_ids)
}

pub fn compute_rune_contract(rune_id: FieldElement) -> FieldElement {
    get_udc_deployed_address(
        FieldElement::ZERO,
        *SAG_CLASS_HASH,
        &UdcUniqueness::NotUnique,
        &[rune_id],
    )
}

pub async fn is_deployed_on_starknet(
    state: &Arc<AppState>,
    contract_address: FieldElement,
) -> Result<()> {
    let _ = state
        .starknet_provider
        .get_class_hash_at(BlockId::Tag(BlockTag::Latest), contract_address)
        .await?;
    Ok(())
}

pub async fn check_last_nonce_update_timestamp(state: &Arc<AppState>) {
    let current_timestamp = get_current_timestamp();
    let five_mn = 5 * 60 * 1000; // in ms
    let last_update = state.transactions.with_last_sent_read(|t| *t).await;

    if current_timestamp - last_update > five_mn {
        // We fetch the nonce
        let new_nonce = if let Ok(nonce) = state.starknet_account.get_nonce().await {
            nonce
        } else {
            state.logger.severe(
                "Unable to retrieve nonce from account in check_last_nonce_update_timestamp",
            );
            return;
        };

        state.transactions.with_nonce(|n| *n = new_nonce).await;
        state
            .transactions
            .with_last_sent(|t| *t = current_timestamp)
            .await;
    }
}
