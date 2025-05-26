use bitcoin::{Block, BlockHash};

use super::BlocksState;

pub trait BlockStateTrait {
    fn init() -> Self;
    fn has_blocks(&self) -> bool;
    fn add_block(&mut self, block: Block);
    fn remove_block(&mut self, block_hash: BlockHash);
    fn get_blocks(&self) -> Vec<Block>;
}

impl BlockStateTrait for BlocksState {
    fn init() -> Self {
        BlocksState { hashes: Vec::new() }
    }

    fn has_blocks(&self) -> bool {
        !self.hashes.is_empty()
    }

    fn add_block(&mut self, block: Block) {
        let mut found = false;
        for b in self.hashes.iter_mut() {
            if b.block_hash() == block.block_hash() {
                found = true;
                *b = block.clone();
                break;
            }
        }
        if !found {
            self.hashes.push(block);
        }
    }

    fn remove_block(&mut self, block_hash: BlockHash) {
        self.hashes.retain(|block| block.block_hash() != block_hash);
    }

    fn get_blocks(&self) -> Vec<Block> {
        self.hashes.clone()
    }
}
