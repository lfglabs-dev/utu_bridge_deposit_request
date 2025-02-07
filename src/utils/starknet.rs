use std::{collections::HashMap, env, str::FromStr};

use anyhow::Result;
use bigdecimal::{num_bigint::BigInt, FromPrimitive, Num};
use num_integer::Integer;
use rust_decimal::Decimal;
use starknet::core::{
    types::Felt,
    utils::{get_udc_deployed_address, UdcUniqueness},
};
use starknet_crypto::poseidon_hash_many;

use crate::models::{hiro::BlockActivityResult, runes::RuneDetail};

lazy_static::lazy_static! {
    static ref RUNE_BRIDGE_CONTRACT: Felt = Felt::from_hex(&env::var("RUNE_BRIDGE_CONTRACT").expect("RUNE_BRIDGE_CONTRACT must be set")).unwrap();
    static ref SAG_CLASS_HASH: Felt = Felt::from_hex(&env::var("SAG_CLASS_HASH").expect("SAG_CLASS_HASH must be set")).unwrap();
    static ref TWO_POW_128: BigInt = BigInt::from(2).pow(128);
}

pub fn compute_hashed_value(
    runes_mapping: &HashMap<String, RuneDetail>,
    tx_data: BlockActivityResult,
    starknet_addr: &str,
) -> Result<(Felt, Felt, (Felt, Felt))> {
    //  Fetch supported rune
    let rune_details = runes_mapping.get(&tx_data.clone().rune.id);
    if rune_details.is_none() {
        return Err(anyhow::anyhow!(format!(
            "Rune not supported: {:?}",
            tx_data.clone().rune.id
        )));
    }
    let rune_details = rune_details.unwrap();
    let rune_id: Felt = symbol_as_felt(&rune_details.symbol);

    let amount = if let Some(amount) = tx_data.clone().amount {
        amount
    } else {
        return Err(anyhow::anyhow!(format!(
            "Amount is not specified: {:?}",
            tx_data.clone().amount
        )));
    };

    let amount_bigint = match convert_to_bigint(&amount, rune_details.divisibility) {
        Ok(amount_bigint) => amount_bigint,
        Err(err) => {
            return Err(anyhow::anyhow!(format!(
                "Amount is not a valid number: {:?}",
                err
            )));
        }
    };
    let amount_felt = to_uint256(amount_bigint);

    let tx_id_felt = if let Ok(tx_id) = hex_to_uint256(&tx_data.location.tx_id) {
        tx_id
    } else {
        return Err(anyhow::anyhow!(format!(
            "Invalid tx_id: {:?}",
            tx_data.location.tx_id
        )));
    };

    let starknet_addr = Felt::from_hex(starknet_addr)?;

    let hashed_value = poseidon_hash_many(&[rune_id, amount_felt.0, starknet_addr, tx_id_felt.0]);

    Ok((hashed_value, rune_id, amount_felt))
}

pub fn symbol_as_felt(symbol: &str) -> Felt {
    let bytes = symbol.as_bytes();
    let mut rune_id_felt: u128 = 0;
    let mut shift_amount: u128 = 1;

    for &byte in bytes.iter() {
        rune_id_felt += (byte as u128) * shift_amount;
        shift_amount *= 256;
    }

    Felt::from(rune_id_felt)
}

pub fn convert_to_bigint(amount: &str, divisibility: u64) -> Result<BigInt> {
    // Parse the amount string to BigDecimal
    let decimal_amount = Decimal::from_str(amount)?;

    // Calculate the multiplicative factor from divisibility
    let factor = Decimal::from_i64(10_i64.pow(divisibility as u32))
        .ok_or_else(|| anyhow::anyhow!("Invalid divisibility factor"))?;

    // Multiply the decimal amount by the factor
    let scaled_amount = decimal_amount * factor;

    // Convert the scaled amount to BigInt (removing any fractional part)
    let bigint_result = BigInt::from_str(&scaled_amount.trunc().to_string())?;

    Ok(bigint_result)
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

pub fn compute_rune_contract(rune_id: Felt) -> Felt {
    get_udc_deployed_address(
        Felt::ZERO,
        *SAG_CLASS_HASH,
        &UdcUniqueness::NotUnique,
        &[rune_id],
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

    use super::*;

    #[test]
    fn test_compute_rune_contract() {
        let symbol = "🐕";
        let symbol_felt = symbol_as_felt(symbol);
        let expected_symbol = Felt::from_dec_str("2509283312").unwrap();
        assert_eq!(symbol_felt, expected_symbol);

        let expected_contract_addr =
            Felt::from_hex("0x01c8C5847aE848Eabf909515338e74DADBC724f54C7735851c57eCfdF1319143")
                .unwrap();
        let computed_contract_addr = compute_rune_contract(symbol_felt);
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
