use std::{collections::HashMap, sync::Arc};

use crate::{
    models::runes::RuneDetail,
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
        rune_map.insert(
            rune.id.clone(),
            RuneDetail {
                symbol: rune.symbol.clone(),
                divisibility: rune.divisibility,
            },
        );
    }

    Ok((supported_runes, rune_map))
}
