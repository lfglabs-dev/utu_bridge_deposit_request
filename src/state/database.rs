use mongodb::{bson::doc, ClientSession, Database};
use utu_bridge_types::{
    bitcoin::{BitcoinAddress, BitcoinTxId},
    starknet::StarknetAddress,
    ClaimedRunesDepositsDocument, DepositAddressesDocument, RunesDocument,
};

use crate::{logger::Logger, models::monitor::FordefiTransaction};

use super::DatabaseError;

pub trait DatabaseExt {
    async fn is_deposit_addr(
        &self,
        receiver_address: BitcoinAddress,
    ) -> Result<StarknetAddress, DatabaseError>;
    async fn get_supported_runes(
        &self,
        session: &mut ClientSession,
        logger: &Logger,
    ) -> Result<Vec<RunesDocument>, DatabaseError>;
    async fn store_fordefi_txs(
        &self,
        session: &mut ClientSession,
        fordefi_tx: FordefiTransaction,
    ) -> Result<(), DatabaseError>;
    async fn was_submitted(
        &self,
        session: &mut ClientSession,
        txid: String,
        output_index: usize,
    ) -> Result<bool, DatabaseError>;
}

impl DatabaseExt for Database {
    async fn is_deposit_addr(
        &self,
        receiver_address: BitcoinAddress,
    ) -> Result<StarknetAddress, DatabaseError> {
        let result = self
            .collection::<DepositAddressesDocument>("deposit_addresses")
            .find_one(doc! {"bitcoin_deposit_address": receiver_address.as_str()})
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
        logger: &Logger,
    ) -> Result<Vec<RunesDocument>, DatabaseError> {
        let mut cursor = self
            .collection::<RunesDocument>("runes")
            .find(doc! {})
            .session(&mut *session)
            .await
            .map_err(|err| {
                logger.severe(format!("Database query failed for runes: {:?}", err));
                DatabaseError::QueryFailed(err)
            })?;

        let mut res: Vec<RunesDocument> = Vec::new();

        while let Some(doc_result) = cursor.next(session).await {
            match doc_result {
                Ok(doc) => res.push(doc),
                Err(err) => {
                    logger.severe(format!("Database query failed for runes: {:?}", err));
                    return Err(DatabaseError::QueryFailed(err));
                }
            }
        }

        Ok(res)
    }

    async fn store_fordefi_txs(
        &self,
        session: &mut ClientSession,
        fordefi_tx: FordefiTransaction,
    ) -> Result<(), DatabaseError> {
        let collection = self.collection::<FordefiTransaction>("fordefi_txs");
        collection
            .insert_one(fordefi_tx)
            .session(&mut *session)
            .await
            .map_err(|e| {
                log::error!("Error inserting fordefi transaction: {:?}", e);
                DatabaseError::QueryFailed(e)
            })?;
        Ok(())
    }

    async fn was_submitted(
        &self,
        session: &mut ClientSession,
        txid: String,
        output_index: usize,
    ) -> Result<bool, DatabaseError> {
        let txid = BitcoinTxId::new(&txid)
            .map_err(|e| anyhow::anyhow!("Invalid transaction ID: {}", e))?;
        let collection = self.collection::<ClaimedRunesDepositsDocument>("claimed_runes_deposits");
        let result = collection
            .find_one(doc! {"tx_id": txid.as_str(), "vout": output_index as u32})
            .session(&mut *session)
            .await
            .map_err(|e| {
                log::error!("Error checking if transaction was submitted: {:?}", e);
                DatabaseError::QueryFailed(e)
            })?;

        match result {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }
}
