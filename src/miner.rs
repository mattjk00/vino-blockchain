use crate::blockchain::{Blockchain, Block, Transaction, s32, s64};
use rand::Rng;

/// Represents a miner. Has a block target that it mines for
pub struct Miner {
    pub target:Block,
    done:bool
}

impl Miner {
    /// Create a new miner with given target block
    pub fn new(t:Block) -> Miner {
        Miner {target:t, done:false}
    }

    /// Generates a random nonce and then attempts to solve valid hash.
    /// 'done' flag will be set to true if a valid hash is found.
    pub fn mine(&mut self) {
        let mut rng = rand::thread_rng();
        let nonce:u32 = rng.gen();
        self.target.nonce = nonce;
        
        let gen_hash = Blockchain::calc_hash(&self.target);
        if Blockchain::has_proof_of_work(gen_hash) {
            self.done = true;
            self.target.hash = gen_hash;
        }
    }

    pub fn is_done(&self) -> bool {
        self.done
    }
}