use crate::blockchain::{Blockchain, Block, Transaction, s32, s64};
use rand::Rng;

pub struct Miner {
    pub target:Block,
    done:bool
}

impl Miner {
    pub fn new(t:Block) -> Miner {
        Miner {target:t, done:false}
    }

    pub fn mine(&mut self) {
        let mut rng = rand::thread_rng();
        let nonce:u32 = rng.gen();
        self.target.nonce = nonce;
        
        let gen_hash = Blockchain::calc_hash(&self.target);
        if gen_hash[0] == 0 && gen_hash[1] == 0 {
            self.done = true;
            self.target.hash = gen_hash;
        }
    }

    pub fn is_done(&self) -> bool {
        self.done
    }
}