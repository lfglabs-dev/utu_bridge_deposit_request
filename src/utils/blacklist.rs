use std::sync::Arc;

use crate::state::{database::DatabaseExt, AppState};
use anyhow::Result;

pub async fn blacklist_deposits(state: &Arc<AppState>, tx_ids: Vec<String>) -> Result<()> {
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

    if let Err(e) = state.db.blacklist_deposits(&mut session, tx_ids).await {
        return Err(anyhow::anyhow!("Database error: {:?}", e));
    }

    if let Err(err) = session.commit_transaction().await {
        return Err(anyhow::anyhow!("Database error: {:?}", err));
    };

    Ok(())
}
