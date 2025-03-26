use std::{collections::HashMap, sync::Arc};

use crate::{
    models::{
        hiro::BlockActivityResult,
        runes::{RuneDetail, RuneId},
    },
    state::{database::DatabaseExt, AppState},
};
use anyhow::Result;

pub async fn get_supported_runes_vec(
    state: &Arc<AppState>,
) -> Result<(Vec<String>, HashMap<String, RuneDetail>)> {
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

    let supported_runes_array = state.db.get_supported_runes(&mut session).await?;

    let mut supported_runes = Vec::new();
    let mut rune_map = HashMap::new();

    for rune in &supported_runes_array {
        supported_runes.push(rune.id.clone());
        let rune_id = RuneId {
            block: rune.id.split(":").next().unwrap().parse::<u64>().unwrap(),
            tx: rune.id.split(":").nth(1).unwrap().parse::<u32>().unwrap(),
        };
        rune_map.insert(
            rune.id.clone(),
            RuneDetail {
                rune_id,
                divisibility: rune.divisibility,
            },
        );
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

    let supported_runes = state.db.get_supported_runes(&mut session).await?;

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
    runes_mapping: &HashMap<String, RuneDetail>,
) -> Result<(RuneId, u64, f64)> {
    let rune = runes_mapping.get(&tx.rune.id);
    if rune.is_none() {
        return Err(anyhow::anyhow!("Rune not found: {}", tx.rune.id));
    }
    let rune = rune.unwrap();

    let amount: f64 = if let Some(amount) = tx.amount.clone() {
        amount.parse::<f64>().unwrap_or(0.0)
    } else {
        0.0
    };

    Ok((rune.rune_id.clone(), rune.divisibility, amount))
}
