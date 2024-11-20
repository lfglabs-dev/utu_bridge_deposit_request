use std::fmt;

use ::starknet::core::types::FieldElement;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::pub_struct;

pub mod bitcoin_rpc;
pub mod general;
pub mod macros;
pub mod starknet;

pub_struct!(Debug, Clone, Copy, PartialEq, Eq; Address {
    felt: FieldElement
});

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let felt = if s.starts_with("0x") {
            FieldElement::from_hex_be(&s)
        } else {
            FieldElement::from_dec_str(&s)
        }
        .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Ok(Address { felt })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.felt.to_bytes_be();
        write!(f, "0x")?;
        for byte in bytes {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl Address {
    pub fn from_str(s: &str) -> Result<Self, String> {
        let felt = if s.starts_with("0x") {
            FieldElement::from_hex_be(s)
        } else {
            FieldElement::from_dec_str(s)
        }
        .map_err(|e| e.to_string())?;

        Ok(Address { felt })
    }
}
