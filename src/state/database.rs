use mongodb::{bson::doc, ClientSession, Database};

use crate::models::{database::DepositAddressDocument, runes::SupportedRuneDocument};

use super::DatabaseError;

pub trait DatabaseExt {
    async fn is_deposit_addr(
        &self,
        session: &mut ClientSession,
        receiver_address: String,
    ) -> Result<String, DatabaseError>;
    async fn get_supported_runes(
        &self,
        session: &mut ClientSession,
    ) -> Result<Vec<SupportedRuneDocument>, DatabaseError>;
}

impl DatabaseExt for Database {
    async fn is_deposit_addr(
        &self,
        session: &mut ClientSession,
        receiver_address: String,
    ) -> Result<String, DatabaseError> {
        let result = self
            .collection::<DepositAddressDocument>("deposit_addresses")
            .find_one(doc! {"bitcoin_deposit_address": receiver_address})
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
    ) -> Result<Vec<SupportedRuneDocument>, DatabaseError> {
        let mut cursor = self
            .collection::<SupportedRuneDocument>("runes")
            .find(doc! {})
            .session(&mut *session)
            .await
            .map_err(DatabaseError::QueryFailed)?;

        let mut res: Vec<SupportedRuneDocument> = Vec::new();

        while let Some(doc_result) = cursor.next(session).await {
            match doc_result {
                Ok(doc) => res.push(doc),
                Err(err) => return Err(DatabaseError::QueryFailed(err)),
            }
        }

        Ok(res)
    }
}
