use std::{collections::HashMap, sync::Arc};

use crate::state::{database::DatabaseExt, AppState};
use anyhow::Result;
use utu_bridge_types::bitcoin::BitcoinRuneId;

pub async fn get_supported_runes_vec(
    state: &Arc<AppState>,
) -> Result<(Vec<String>, HashMap<String, (BitcoinRuneId, u32)>)> {
    let mut session = match state.db.client().start_session().await {
        Ok(session) => session,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "Database error: unable to start session".to_string()
            ));
        }
    };

    let supported_runes_array = state
        .db
        .get_supported_runes(&mut session, &state.logger)
        .await?;

    let mut supported_runes = Vec::new();
    let mut rune_map = HashMap::new();

    for rune in &supported_runes_array {
        supported_runes.push(rune.spaced_name.clone());
        rune_map.insert(
            rune.spaced_name.clone(),
            (rune.id.clone(), rune.divisibility),
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
