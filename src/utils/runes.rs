use std::sync::Arc;

use crate::state::{database::DatabaseExt, AppState};
use anyhow::Result;

pub async fn get_supported_runes_vec(state: &Arc<AppState>) -> Result<Vec<String>> {
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
    let supported_runes = supported_runes_array
        .iter()
        .map(|rune| rune.id.clone())
        .collect::<Vec<String>>();

    Ok(supported_runes)
}
