use std::{env, sync::Arc};

use anyhow::Result;
use bigdecimal::num_bigint::BigInt;
use num_integer::Integer;
use reqwest::Url;
use starknet::{
    accounts::{ConnectedAccount, SingleOwnerAccount},
    core::{
        types::{BlockId, BlockTag, Call, Felt},
        utils::{get_udc_deployed_address, UdcUniqueness},
    },
    macros::selector,
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::{LocalWallet, SigningKey},
};

use crate::{models::claim::ClaimCalldata, state::AppState};

use super::general::get_current_timestamp;

lazy_static::lazy_static! {
    static ref RUNE_BRIDGE_CONTRACT: Felt = Felt::from_hex(&env::var("RUNE_BRIDGE_CONTRACT").expect("RUNE_BRIDGE_CONTRACT must be set")).unwrap();
    static ref SAG_CLASS_HASH: Felt = Felt::from_hex(&env::var("SAG_CLASS_HASH").expect("SAG_CLASS_HASH must be set")).unwrap();
    static ref TWO_POW_128: BigInt = BigInt::from(2).pow(128);
}

pub async fn get_account() -> SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet> {
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse(&env::var("STARKNET_RPC_URL").expect("STARKNET_RPC_URL must be set")).unwrap(),
    ));
    let chainid = provider.chain_id().await.unwrap();
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(
        Felt::from_hex(&env::var("ACCOUNT_PRIV_KEY").expect("ACCOUNT_PRIV_KEY must be set"))
            .unwrap(),
    ));
    SingleOwnerAccount::new(
        provider,
        signer,
        Felt::from_hex(&env::var("ACCOUNT_ADDRESS").expect("ACCOUNT_ADDRESS must be set")).unwrap(),
        chainid,
        starknet::accounts::ExecutionEncoding::New,
    )
}

pub async fn prepare_multicall(
    state: &Arc<AppState>,
    transactions: Vec<ClaimCalldata>,
) -> (Vec<Call>, Vec<String>) {
    let mut calls: Vec<Call> = Vec::new();
    let mut tx_ids: Vec<String> = Vec::new();

    for transaction in transactions {
        // ensure the rune contract is deployed
        let rune_contract = compute_rune_contract(transaction.rune_id);
        if is_deployed_on_starknet(state, rune_contract).await.is_ok() {
            let mut calldata = vec![
                transaction.rune_id,
                transaction.amount.0,
                transaction.amount.1,
                transaction.target_addr.felt,
            ];
            calldata.extend(transaction.tx_id.iter());
            calldata.push(transaction.tx_vout);
            // todo: put the sig we get from fordefi instead
            // calldata.push(transaction.sig.r);
            // calldata.push(transaction.sig.s);
            calldata.extend(transaction.transaction_struct.iter());

            calls.push(Call {
                to: *RUNE_BRIDGE_CONTRACT,
                selector: selector!("claim_runes"),
                calldata,
            });
            tx_ids.push(transaction.tx_id_str);
        }
    }

    (calls, tx_ids)
}

pub fn compute_rune_contract(rune_id: Felt) -> Felt {
    get_udc_deployed_address(
        Felt::ZERO,
        *SAG_CLASS_HASH,
        &UdcUniqueness::NotUnique,
        &[rune_id],
    )
}

pub async fn is_deployed_on_starknet(state: &Arc<AppState>, contract_address: Felt) -> Result<()> {
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

#[allow(dead_code)]
pub fn to_uint256(n: BigInt) -> (Felt, Felt) {
    let (n_high, n_low) = n.div_rem(&TWO_POW_128);
    let (_, low_bytes) = n_low.to_bytes_be();
    let (_, high_bytes) = n_high.to_bytes_be();

    (
        Felt::from_bytes_be_slice(&low_bytes),
        Felt::from_bytes_be_slice(&high_bytes),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbol_as_felt(symbol: String) -> Felt {
        let bytes = symbol.as_bytes();
        let mut rune_id_felt: u128 = 0;
        let mut shift_amount: u128 = 1;

        for &byte in bytes.iter() {
            rune_id_felt += (byte as u128) * shift_amount;
            shift_amount *= 256;
        }

        Felt::from(rune_id_felt)
    }

    #[test]
    fn test_compute_rune_contract() {
        let symbol = "🐕";
        let symbol_felt = symbol_as_felt(symbol.to_string());
        let expected_symbol = Felt::from_dec_str("2509283312").unwrap();
        assert_eq!(symbol_felt, expected_symbol);

        let expected_contract_addr =
            Felt::from_hex("0x01c8C5847aE848Eabf909515338e74DADBC724f54C7735851c57eCfdF1319143")
                .unwrap();
        let computed_contract_addr = compute_rune_contract(symbol_felt);
        assert_eq!(computed_contract_addr, expected_contract_addr);
    }
}
