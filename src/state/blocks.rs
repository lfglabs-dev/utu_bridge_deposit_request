use bitcoin::BlockHash;

use super::BlocksState;

pub trait BlockStateTrait {
    fn init() -> Self;
    fn has_blocks(&self) -> bool;
    fn add_block(&mut self, block: BlockHash);
    fn remove_block(&mut self, block: BlockHash);
    fn get_blocks(&self) -> Vec<BlockHash>;
}

impl BlockStateTrait for BlocksState {
    fn init() -> Self {
        BlocksState { hashes: Vec::new() }
    }

    fn has_blocks(&self) -> bool {
        !self.hashes.is_empty()
    }

    fn add_block(&mut self, block: BlockHash) {
        self.hashes.push(block);
    }

    fn remove_block(&mut self, block: BlockHash) {
        self.hashes.retain(|hash| *hash != block);
    }

    fn get_blocks(&self) -> Vec<BlockHash> {
        self.hashes.clone()
    }
}
