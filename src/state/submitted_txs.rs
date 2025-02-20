use super::SubmittedTxsState;

pub trait SubmittedTxsStateTrait {
    fn init() -> Self;
    fn has_tx(&self, tx: String) -> bool;
    fn add_tx(&mut self, tx: String);
}

impl SubmittedTxsStateTrait for SubmittedTxsState {
    fn init() -> Self {
        SubmittedTxsState { txs: Vec::new() }
    }

    fn has_tx(&self, tx: String) -> bool {
        self.txs.contains(&tx)
    }

    fn add_tx(&mut self, tx: String) {
        self.txs.push(tx);
    }
}
