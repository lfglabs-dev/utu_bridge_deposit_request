use bitcoin::BlockHash;
use bitcoincore_rpc::{
    json::{GetBlockHeaderResult, GetRawTransactionResult, GetRawTransactionResultVinScriptSig},
    RpcApi,
};
use starknet::core::types::Felt;

use crate::utils::byte_array::ByteArray;

pub fn get_transaction_struct_felt(
    bitcoin_provider: &bitcoincore_rpc::Client,
    raw_tx: GetRawTransactionResult,
) -> Vec<Felt> {
    // add version, is_segwit, locktime
    let mut res: Vec<Felt> = vec![Felt::from(raw_tx.version), Felt::ZERO];

    // add inputs
    let mut input_len = 0;
    let mut input_calldata: Vec<Felt> = Vec::new();
    for input in raw_tx.vin {
        // get raw transaction data from input txid
        let input_tx = match bitcoin_provider.get_raw_transaction_info(&input.txid.unwrap(), None) {
            Ok(tx_info) => tx_info,
            Err(_) => {
                continue;
            }
        };

        // get block header
        let block_header = get_block_header(bitcoin_provider, input_tx.blockhash.unwrap());
        if block_header.is_none() {
            continue;
        }
        let block_header = block_header.unwrap();

        // Add script
        let script = ByteArray::to_calldata(
            &input
                .clone()
                .script_sig
                .unwrap_or(GetRawTransactionResultVinScriptSig {
                    hex: vec![],
                    asm: "".to_string(),
                })
                .hex,
        );
        input_calldata.extend(script.iter());

        // Add sequence
        input_calldata.push(Felt::from(input.clone().sequence));

        // Add previous_output: OutPoint
        input_calldata.extend(hex_to_hash_rev(input.clone().txid));
        input_calldata.push(Felt::from(input.vout.unwrap_or(0)));

        // data: TxOut
        if input.vout.is_some() {
            let vout_index = input.vout.unwrap();
            let vout = input_tx.vout[vout_index as usize].clone();

            input_calldata.push(Felt::from(vout.value.to_sat())); // value
            let pk_script = ByteArray::to_calldata(&vout.script_pub_key.hex);
            input_calldata.extend(pk_script.iter());
            input_calldata.push(Felt::ZERO);
        } else {
            input_calldata.push(Felt::ZERO); // value
            input_calldata.push(Felt::ZERO); // pk script
            input_calldata.push(Felt::ZERO);
            input_calldata.push(Felt::ZERO);
            input_calldata.push(Felt::ZERO); // cached
        }

        input_calldata.push(Felt::from(block_header.height as u32)); // block_height
        input_calldata.push(Felt::from(block_header.median_time.unwrap_or(0) as u32)); // median_time_past
        input_calldata.push(Felt::from(if input.is_coinbase() { 1 } else { 0 })); // is_coinbase

        // Add witness
        let witness = get_witness(input.txinwitness.unwrap_or(vec![]));
        input_calldata.extend(witness.iter());

        input_len += 1;
    }
    // add inputs data to res
    res.push(Felt::from(input_len as u32));
    res.extend(input_calldata.iter());

    // add outputs
    let mut outputs: Vec<Felt> = Vec::new();
    outputs.push(Felt::from(raw_tx.vout.len() as u32));
    res.push(Felt::from(raw_tx.vout.len() as u32));
    for output in raw_tx.vout {
        // value
        res.push(Felt::from(output.value.to_sat()));
        outputs.push(Felt::from(output.value.to_sat()));
        // pk script
        let pk_script = ByteArray::to_calldata(&output.script_pub_key.hex);
        res.extend(pk_script.iter());
        outputs.extend(pk_script.iter());
        // cached
        res.push(Felt::ZERO);
        outputs.push(Felt::ZERO);
    }

    // add lock time
    res.push(Felt::from(raw_tx.locktime));
    res
}

fn get_block_header(
    bitcoin_provider: &bitcoincore_rpc::Client,
    block_hash: BlockHash,
) -> Option<GetBlockHeaderResult> {
    match bitcoin_provider.get_block_header_info(&block_hash) {
        Ok(block_header) => Some(block_header),
        Err(_) => None,
    }
}

fn get_witness(data: Vec<Vec<u8>>) -> Vec<Felt> {
    let mut res: Vec<Felt> = Vec::new();
    res.push(Felt::from(data.len() as u32));
    for w in data {
        let arr = ByteArray::to_calldata(&w);
        res.extend(arr.iter());
    }
    res
}

pub fn hex_to_hash_rev(tx_id: Option<bitcoin::Txid>) -> Vec<Felt> {
    match tx_id {
        Some(txid) => {
            let hex_string = txid.to_string(); // Convert Txid to hex string
            let hex_bytes = hex_string.as_bytes();
            let len = hex_bytes.len();

            let mut result: Vec<u32> = Vec::new();
            let mut unit: u32 = 0;

            let mut i = 0;
            while i < len {
                // Push a new unit after every 4 bytes (8 hex chars)
                if i != 0 && i % 8 == 0 {
                    result.push(unit);
                    unit = 0;
                }

                // Reverse high and low nibbles
                let hi = hex_char_to_nibble(hex_bytes[len - i - 2]);
                let lo = hex_char_to_nibble(hex_bytes[len - i - 1]);
                unit = (unit << 8) | ((hi << 4) | lo) as u32;

                i += 2;
            }

            // Push the last unit if not already added
            if unit != 0 {
                result.push(unit);
            }

            // Pad with zeros to ensure 8 values
            while result.len() < 8 {
                result.push(0);
            }

            // Convert to Felt and return
            result.into_iter().map(Felt::from).collect()
        }
        None => vec![Felt::from(0); 8], // Return 8 zeros if None
    }
}

pub fn hex_char_to_nibble(hex_char: u8) -> u8 {
    match hex_char {
        b'0'..=b'9' => hex_char - b'0',
        b'A'..=b'F' => hex_char - b'A' + 10,
        b'a'..=b'f' => hex_char - b'a' + 10,
        _ => panic!("Invalid hex character: {}", hex_char as char),
    }
}

#[allow(dead_code)]
pub fn from_hex(hex_string: &str) -> Vec<u8> {
    assert!(
        hex_string.len() % 2 == 0,
        "Hex string must have an even length"
    );

    hex_string
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let hi = hex_char_to_nibble(chunk[0]);
            let lo = hex_char_to_nibble(chunk[1]);
            (hi << 4) | lo
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{env, str::FromStr};

    use bitcoin::Txid;
    use bitcoincore_rpc::{Auth, RpcApi};
    use starknet::{core::types::Felt, macros::felt};

    use crate::utils::calldata::hex_to_hash_rev;

    use super::get_transaction_struct_felt;

    #[test]
    fn test_txid_to_hex_to_hash_rev() {
        let tx_id =
            Txid::from_str("fb22bfe293861a90f2115257ee4d06965b46e8a4f41dfc95f4968558b0f6e06d")
                .unwrap();
        let digest = hex_to_hash_rev(Some(tx_id));
        let expected_result: Vec<Felt> = vec![
            Felt::from_dec_str("1843459760").unwrap(),
            Felt::from_dec_str("1485149940").unwrap(),
            Felt::from_dec_str("2516327924").unwrap(),
            Felt::from_dec_str("2766685787").unwrap(),
            Felt::from_dec_str("2516995566").unwrap(),
            Felt::from_dec_str("1464996338").unwrap(),
            Felt::from_dec_str("2417657491").unwrap(),
            Felt::from_dec_str("3804177147").unwrap(),
        ];
        assert_eq!(digest, expected_result);
    }

    #[tokio::test]
    async fn test_calldata() {
        let bitcoin_rpc_user = env::var("BITCOIN_RPC_USER").expect("BITCOIN_RPC_USER must be set");
        let bitcoin_rpc_password =
            env::var("BITCOIN_RPC_PASSWORD").expect("BITCOIN_RPC_PASSWORD must be set");
        let bitcoin_auth = if bitcoin_rpc_user.is_empty() || bitcoin_rpc_password.is_empty() {
            Auth::None
        } else {
            Auth::UserPass(bitcoin_rpc_user, bitcoin_rpc_password)
        };

        let bitcoin_provider = bitcoincore_rpc::Client::new("btc.lfg.rs", bitcoin_auth).unwrap();
        let transaction_id = "da8cd9cc1c9b8a0b2ba9726065b3302bff8a1790559f85f85fcf062759348042";

        let raw_tx = bitcoin_provider
            .get_raw_transaction_info(&Txid::from_str(transaction_id).unwrap(), None)
            .unwrap();

        let calldata = get_transaction_struct_felt(&bitcoin_provider, raw_tx);

        let expected_res: Vec<Felt> = vec![
            Felt::TWO,
            Felt::ZERO,
            Felt::ONE,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            felt!("0xffffffff"),
            felt!("0x6de0f6b0"),
            felt!("0x588596f4"),
            felt!("0x95fc1df4"),
            felt!("0xa4e8465b"),
            felt!("0x96064dee"),
            felt!("0x575211f2"),
            felt!("0x901a8693"),
            felt!("0xe2bf22fb"),
            Felt::ZERO,
            felt!("0xc63"),
            Felt::ONE,
            felt!("0x512079a2aa2c82cd13dadc5e3c38338406b291a2c26c39feb5a65f08e49853"),
            felt!("0x5c4109"),
            Felt::THREE,
            Felt::ZERO,
            felt!("0xd540c"),
            felt!("0x6752a77f"),
            Felt::ZERO,
            Felt::ONE,
            Felt::TWO,
            felt!("0xf3199e905926f317c3f72f839028d5968bc3cc50efffa24a15e99e619d7c36"),
            felt!("0x466e5c0bb9caa3b6bbdd2b5f4a74038de691abaa86156c3ccfbd1a69003a86"),
            felt!("0x90c2"),
            Felt::TWO,
            Felt::TWO,
            felt!("0xa56"),
            Felt::ONE,
            felt!("0x512079a2aa2c82cd13dadc5e3c38338406b291a2c26c39feb5a65f08e49853"),
            felt!("0x5c4109"),
            Felt::THREE,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            felt!("0x6a5d0714c0a23314b802"),
            felt!("0xa"),
            Felt::ZERO,
            Felt::ZERO,
        ];

        assert_eq!(calldata, expected_res);
    }
}
