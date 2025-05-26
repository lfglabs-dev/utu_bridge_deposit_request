use std::{collections::HashMap, env};

use anyhow::Result;
use bigdecimal::{num_bigint::BigInt, Num};
use num_integer::Integer;
use starknet::core::{
    types::Felt,
    utils::{get_udc_deployed_address, UdcUniqueness},
};
use starknet_crypto::poseidon_hash_many;
use utu_bridge_types::{bitcoin::BitcoinRuneId, starknet::StarknetAddress};

lazy_static::lazy_static! {
    static ref RUNE_BRIDGE_CONTRACT: Felt = Felt::from_hex(&env::var("RUNE_BRIDGE_CONTRACT").expect("RUNE_BRIDGE_CONTRACT must be set")).unwrap();
    static ref SAG_CLASS_HASH: Felt = Felt::from_hex(&env::var("SAG_CLASS_HASH").expect("SAG_CLASS_HASH must be set")).unwrap();
    static ref TWO_POW_128: BigInt = BigInt::from(2).pow(128);
}

pub fn compute_hashed_value(
    runes_mapping: &HashMap<String, (BitcoinRuneId, u32)>,
    rune_name: String,
    amount: u128,
    tx_id: &str,
    starknet_addr: &StarknetAddress,
) -> Result<(Felt, Felt, Felt, (Felt, Felt))> {
    //  Fetch supported rune
    let rune_data = runes_mapping.get(&rune_name);
    if rune_data.is_none() {
        return Err(anyhow::anyhow!(format!(
            "Rune not supported: {:?}",
            rune_name
        )));
    }
    let (rune_id, _) = rune_data.unwrap();

    let rune_id_block = Felt::from_dec_str(&rune_id.block().to_string())?;
    let rune_id_tx = Felt::from_dec_str(&rune_id.tx().to_string())?;
    let amount_bigint = BigInt::from(amount);
    let amount_felt = to_uint256(amount_bigint);

    let tx_id_felt = if let Ok(tx_id) = hex_to_uint256(&tx_id) {
        tx_id
    } else {
        return Err(anyhow::anyhow!(format!("Invalid tx_id: {:?}", tx_id)));
    };

    let hashed_value = poseidon_hash_many(&[
        rune_id_block,
        rune_id_tx,
        amount_felt.0,
        starknet_addr.felt,
        tx_id_felt.0,
    ]);

    Ok((hashed_value, rune_id_block, rune_id_tx, amount_felt))
}

pub fn hex_to_uint256(hex_str: &str) -> Result<(Felt, Felt)> {
    // Parse the hexadecimal string into a BigInt
    let n = BigInt::from_str_radix(hex_str, 16)?;

    // Split the BigInt into two 128-bit chunks (high and low)
    let (n_high, n_low) = n.div_rem(&TWO_POW_128);

    // Convert the chunks to byte arrays and then to Felt
    let (_, low_bytes) = n_low.to_bytes_be();
    let (_, high_bytes) = n_high.to_bytes_be();

    Ok((
        Felt::from_bytes_be_slice(&low_bytes),
        Felt::from_bytes_be_slice(&high_bytes),
    ))
}

pub fn compute_rune_contract(rune_id_block: Felt, rune_id_tx: Felt) -> Felt {
    get_udc_deployed_address(
        Felt::ZERO,
        *SAG_CLASS_HASH,
        &UdcUniqueness::NotUnique,
        &[rune_id_block, rune_id_tx],
    )
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
    use starknet::macros::felt;
    use utu_bridge_types::bitcoin::BitcoinRuneId;

    use super::*;

    #[test]
    fn test_compute_rune_contract() {
        let rune_id = BitcoinRuneId::new(840000, 3);

        let expected_contract_addr =
            felt!("0x40e81cfeb176bfdbc5047bbc55eb471cfab20a6b221f38d8fda134e1bfffca4");
        let computed_contract_addr = compute_rune_contract(
            Felt::from_dec_str(&rune_id.block().to_string()).unwrap(),
            Felt::from_dec_str(&rune_id.tx().to_string()).unwrap(),
        );
        assert_eq!(computed_contract_addr, expected_contract_addr);
    }

    #[test]
    fn test_hex_to_uint256() {
        let hex_tx_id = "a8d6ed49c8177545d81e1aee2fabb8d75bc07ae0cf0f469d165b2ca505d5e117";

        // Digest in cairo should be equal to the value below, using hex_to_hash_rev from auto_claim
        // [0x17e1d505, 0xa52c5b16, 0x9d460fcf, 0xe07ac05b, 0xd7b8ab2f, 0xee1a1ed8, 0x457517c8, 0x49edd6a8]
        // which is equal to { low: 121959160878427944421643839789432430871, high: 224426267596249609810929133391035742423) }

        let expected_low = felt!("121959160878427944421643839789432430871");
        let expected_high = felt!("224426267596249609810929133391035742423");

        let (low, high) = hex_to_uint256(hex_tx_id).unwrap();

        assert!(low == expected_low);
        assert!(high == expected_high);
    }
}
