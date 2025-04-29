use std::{collections::HashMap, str::FromStr, sync::Arc};

use crate::{
    models::hiro::BlockActivityResult,
    state::{database::DatabaseExt, AppState},
};
use anyhow::Result;
use utu_bridge_types::bitcoin::BitcoinRuneId;

pub async fn get_supported_runes_vec(
    state: &Arc<AppState>,
) -> Result<(Vec<BitcoinRuneId>, HashMap<BitcoinRuneId, u32>)> {
    let mut session = match state.db.client().start_session().await {
        Ok(session) => session,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "Database error: unable to start session".to_string()
            ));
        }
    };
    if let Err(err) = session.start_transaction().await {
        return Err(anyhow::anyhow!("Database error: {:?}", err));
    };

    let supported_runes_array = state
        .db
        .get_supported_runes(&mut session, &state.logger)
        .await?;

    let mut supported_runes = Vec::new();
    let mut rune_map = HashMap::new();

    for rune in &supported_runes_array {
        supported_runes.push(rune.id.clone());
        rune_map.insert(rune.id.clone(), rune.divisibility);
    }

    Ok((supported_runes, rune_map))
}

pub async fn log_supported_runes(state: &Arc<AppState>) -> Result<()> {
    let mut session = match state.db.client().start_session().await {
        Ok(session) => session,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "Database error: unable to start session".to_string()
            ));
        }
    };
    if let Err(err) = session.start_transaction().await {
        return Err(anyhow::anyhow!("Database error: {:?}", err));
    };

    let supported_runes = state
        .db
        .get_supported_runes(&mut session, &state.logger)
        .await?;

    let mut formatted_runes = String::from("Supported runes:\n");
    for rune in supported_runes {
        formatted_runes.push_str(&format!("  - {} {}\n", rune.spaced_name, rune.symbol));
    }
    // Remove the last newline if it exists
    if formatted_runes.ends_with('\n') {
        formatted_runes.pop();
    }
    state.logger.info(formatted_runes);

    Ok(())
}

pub fn get_rune_details(
    tx: &BlockActivityResult,
    runes_mapping: &HashMap<BitcoinRuneId, u32>,
) -> Result<(BitcoinRuneId, u32, f64)> {
    let divisibility = runes_mapping.get(&BitcoinRuneId::from_str(&tx.rune.id)?);
    if divisibility.is_none() {
        return Err(anyhow::anyhow!("Rune not found: {}", tx.rune.id));
    }
    let divisibility = divisibility.unwrap();

    let amount: f64 = if let Some(amount) = tx.amount.clone() {
        amount.parse::<f64>().unwrap_or(0.0)
    } else {
        0.0
    };

    let rune_id = BitcoinRuneId::from_str(&tx.rune.id)?;

    Ok((rune_id, *divisibility, amount))
}
