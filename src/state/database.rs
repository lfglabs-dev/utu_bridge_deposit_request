use mongodb::{bson::doc, ClientSession, Database};
use utu_bridge_types::{
    bitcoin::BitcoinAddress, starknet::StarknetAddress, DepositAddressesDocument, RunesDocument,
};

use super::DatabaseError;

pub trait DatabaseExt {
    async fn is_deposit_addr(
        &self,
        session: &mut ClientSession,
        receiver_address: BitcoinAddress,
    ) -> Result<StarknetAddress, DatabaseError>;
    async fn get_supported_runes(
        &self,
        session: &mut ClientSession,
    ) -> Result<Vec<RunesDocument>, DatabaseError>;
}

impl DatabaseExt for Database {
    async fn is_deposit_addr(
        &self,
        session: &mut ClientSession,
        receiver_address: BitcoinAddress,
    ) -> Result<StarknetAddress, DatabaseError> {
        let result = self
            .collection::<DepositAddressesDocument>("deposit_addresses")
            .find_one(doc! {"bitcoin_deposit_address": receiver_address.as_str()})
            .session(&mut *session)
            .await
            .map_err(DatabaseError::QueryFailed)?;

        match result {
            Some(doc) => Ok(doc.starknet_address),
            None => Err(DatabaseError::NotFound),
        }
    }

    async fn get_supported_runes(
        &self,
        session: &mut ClientSession,
    ) -> Result<Vec<RunesDocument>, DatabaseError> {
        let mut cursor = self
            .collection::<RunesDocument>("runes")
            .find(doc! {})
            .session(&mut *session)
            .await
            .map_err(DatabaseError::QueryFailed)?;

        let mut res: Vec<RunesDocument> = Vec::new();

        while let Some(doc_result) = cursor.next(session).await {
            match doc_result {
                Ok(doc) => res.push(doc),
                Err(err) => return Err(DatabaseError::QueryFailed(err)),
            }
        }

        Ok(res)
    }
}
