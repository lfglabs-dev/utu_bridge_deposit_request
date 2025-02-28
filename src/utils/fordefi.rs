use anyhow::Result;
use base64::engine::general_purpose::{self, STANDARD as BASE64_ENGINE};
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs};

use crate::models::claim::FordefiDepositData;

lazy_static::lazy_static! {
    static ref FORDEFI_API_URL: String = env::var("FORDEFI_API_URL").expect("FORDEFI_API_URL must be set");
    static ref FORDEFI_API_USER_ACCESS_TOKEN: String = env::var("FORDEFI_API_USER_ACCESS_TOKEN").expect("FORDEFI_API_USER_ACCESS_TOKEN must be set");
    static ref FORDEFI_PRIVATE_KEY_FILE_PATH: String = env::var("FORDEFI_PRIVATE_KEY_FILE_PATH").expect("FORDEFI_PRIVATE_KEY_FILE_PATH must be set");
    static ref FORDEFI_DEPOSIT_VAULT_ID: String = env::var("FORDEFI_DEPOSIT_VAULT_ID").expect("FORDEFI_DEPOSIT_VAULT_ID must be set");
}

#[derive(Deserialize)]
struct FordefiResponse {
    id: String,
    #[serde(skip)]
    _rest: serde::de::IgnoredAny,
}

pub async fn send_fordefi_request(claim_data: FordefiDepositData) -> Result<String> {
    let raw_data = if let Ok(raw_data) = get_raw_data(claim_data.hashed_value.to_fixed_hex_string())
    {
        raw_data
    } else {
        return Err(anyhow::anyhow!(
            "Error while encoding typed message data into hex string"
        ));
    };

    let note = if let Ok(note) = encode_data(claim_data) {
        note
    } else {
        return Err(anyhow::anyhow!(
            "Error while converting claim_data as string"
        ));
    };

    let request_body = if let Ok(request_body) = get_fordefi_request_body(raw_data, note) {
        request_body
    } else {
        return Err(anyhow::anyhow!("Error while getting request body"));
    };

    let path = "/api/v1/transactions";
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();
    let payload = format!("{path}|{timestamp}|{request_body}");

    let private_key_path = &*FORDEFI_PRIVATE_KEY_FILE_PATH;
    let priv_pem = fs::read_to_string(private_key_path).expect("Failed to read pem file");
    let private_key = p256::SecretKey::from_sec1_pem(&priv_pem).expect("Failed to decode pem key");
    let signing_key: SigningKey = private_key.into();

    let signature: Signature = signing_key.sign(payload.as_bytes());
    let formatted_signature = general_purpose::STANDARD.encode(signature.to_der().to_bytes());
    let client = reqwest::Client::new();
    let res = client
        .post(format!("https://{}{}", *FORDEFI_API_URL, path))
        .body(request_body)
        .bearer_auth(FORDEFI_API_USER_ACCESS_TOKEN.clone())
        .header("Content-Type", "application/json")
        .header("X-Timestamp", timestamp)
        .header("X-Signature", formatted_signature)
        .send()
        .await;

    match res {
        Ok(response) => {
            if response.status().is_success() {
                let response_data = response.json::<FordefiResponse>().await?;
                Ok(response_data.id)
            } else {
                Err(anyhow::anyhow!(format!(
                    "Request failed with status code: {} and response {}",
                    response.status(),
                    response.text().await?
                )))
            }
        }
        Err(e) => Err(anyhow::anyhow!(format!("Request failed with error: {}", e))),
    }
}

/// Encode FordefiDepositData using json + base64 even though bincode would be smaller
/// because the data will have to be decoded in a Python script which we want to keep simple.
fn encode_data(claim_data: FordefiDepositData) -> Result<String> {
    let json_string = serde_json::to_string(&claim_data)?;
    let base64_encoded = BASE64_ENGINE.encode(json_string);
    Ok(base64_encoded)
}

fn get_raw_data(hashed_value: String) -> Result<String> {
    let typed_data: Value = json!({
        "types": {
            "StarknetDomain": [
                { "name": "name", "type": "shortstring" },
                { "name": "version", "type": "shortstring" },
                { "name": "chainId", "type": "shortstring" },
                { "name": "revision", "type": "shortstring" }
            ],
            "ClaimStruct": [
                { "name": "Operation", "type": "shortstring" },
                { "name": "Hashed value", "type": "felt" }
            ]
        },
        "primaryType": "ClaimStruct",
        "domain": {
            "name": "Utu Runes Bridge",
            "version": "1",
            "chainId": "SN_MAIN",
            "revision": "1"
        },
        "message": {
            "Operation": "UtuRunesBridge: Claim",
            "Hashed value": hashed_value
        }
    });

    let formatted_json = serde_json::to_string_pretty(&typed_data)?;
    let hex_encoded = format!("0x{}", hex::encode(formatted_json));
    Ok(hex_encoded)
}

pub fn get_fordefi_request_body(raw_data: String, note: String) -> Result<String> {
    let request = json!({
        "vault_id": *FORDEFI_DEPOSIT_VAULT_ID,
        "note": note,
        "signer_type": "api_signer",
        "sign_mode": "auto",
        "dapp_info": {
            "url": "https://bridge.bitcoin-on-starknet.com/",
            "name": "Utu Bridge Deposit"
        },
        "type": "starknet_message",
        "details": {
            "type": "typed_message_type",
            "chain": "starknet_mainnet",
            "raw_data": raw_data
        }
    });
    let request_str = serde_json::to_string(&request)?;
    Ok(request_str)
}

#[cfg(test)]
mod tests {
    use starknet::{core::types::TypedData, macros::felt};
    use starknet_crypto::{verify, Felt};

    #[test]
    fn test_verify_sig() {
        let fordefi_vault_addr =
            felt!("0x04891b09fb57529541ea78296fe07857dbd518d45007eea78f2271b9c82f652b");

        let raw_typed_data = r#"{
            "types": {
                "StarknetDomain": [
                    { "name": "name", "type": "shortstring" },
                    { "name": "version", "type": "shortstring" },
                    { "name": "chainId", "type": "shortstring" },
                    { "name": "revision", "type": "shortstring" }
                ],
                "ClaimStruct": [
                    { "name": "Operation", "type": "shortstring" },
                    { "name": "Hashed value", "type": "felt" }
                ]
            },
            "primaryType": "ClaimStruct",
            "domain": {
                "name": "Utu Runes Bridge",
                "version": "1",
                "chainId": "SN_MAIN",
                "revision": "1"
            },
            "message": {
                "Operation": "UtuRunesBridge: Claim",
                "Hashed value": "0x02ffb402c24b7680c0b8be3f25e6af70806c4a2b123ad3a43753cd2fddace83c"
            }
        }"#;
        let typed_data = serde_json::from_str::<TypedData>(raw_typed_data).unwrap();
        let computed_msg_hash = typed_data.message_hash(fordefi_vault_addr).unwrap();

        // Message hash received from Fordefi for transaction_id = "dda5a722-fc87-4e44-9854-3cd7581d87cc"
        let msg_hash_received =
            felt!("0x056f72aab803a7ed48dbebbcbdb886d7c5b0156955de69b65779829a9cbd2ea6");

        assert_eq!(computed_msg_hash, msg_hash_received);

        // Signature received from Fordefi for transaction_id = "dda5a722-fc87-4e44-9854-3cd7581d87cc"
        let starknet_signatures = [
            Felt::from_hex("0x1").unwrap(),
            Felt::from_hex("0x0").unwrap(),
            Felt::from_hex("0x4706118c68a14d246af55f20d1df30f50e7d0d12251823cb75597260ff423bb")
                .unwrap(),
            Felt::from_hex("0x2b5f51f73717ed9b75a21b742b30cd1752471e925b56faca0a78ee6b1160d40")
                .unwrap(),
            Felt::from_hex("0x550924a97d33da6056c44751f62a5078ae23d56e15cf23a9ad6c857d017dd9")
                .unwrap(),
        ];

        // Verify the signature
        let res = verify(
            &starknet_signatures[2],
            &msg_hash_received,
            &starknet_signatures[3],
            &starknet_signatures[4],
        )
        .unwrap();
        assert!(res);
    }
}
