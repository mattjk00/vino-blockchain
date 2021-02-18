use sha2::{Sha256, Digest};
use chrono::{DateTime, NaiveDateTime, Utc};
use std::fmt;

struct Blockchain {
    chain:Vec<Block>
}
impl Blockchain {
    fn new() -> Blockchain {
        Blockchain { chain:Vec::new() }
    }

    fn push(&mut self, b:Block) -> bool {
        let last_block = self.chain.last();
        match last_block {
            Some(v) => {
                let block_okay = Blockchain::validate(&v, &b);
                if block_okay {
                    self.chain.push(b);
                }
                block_okay
            },
            None => {
                self.chain.push(b);
                true
            }
        }
    }

    fn replace_chain(&mut self, ch:Vec<Block>) {
        if ch.len() > self.chain.len() {
            self.chain = ch;
        }
    }

    fn print_all(self) {
        for b in self.chain {
            println!("{}, ", b.to_string());
        }
    }

    
    fn calc_hash(b:&Block) -> String {
        let mut hasher = Sha256::new();
        let record = String::from(format!("{}{}{}", b.index, b.timestamp, b.prevhash));
        hasher.update(record);
        let result:[u8; 32] = hasher.finalize().into();
        let mut fullhash = String::new();
        for x in result.iter() {
            fullhash = fullhash + &format!("{}", x);
        }
        fullhash
    }
    
    fn validate(old_block:&Block, new_block:&Block) -> bool {
        old_block.index + 1 == new_block.index && old_block.hash == new_block.prevhash && Blockchain::calc_hash(&new_block) == new_block.hash
    }
}

struct Block {
    index:u32,
    timestamp:String,
    hash:String,
    prevhash:String
}

impl Block {
    fn new(i:u32, prhash:&String) -> Block {
        let time = Utc::now().timestamp().to_string();
        let mut nb = Block {
            index:i,
            timestamp:time,
            prevhash:prhash.to_string(),
            hash:String::new()
        };
        let hash = Blockchain::calc_hash(&nb);
        nb.hash = hash;
        nb
    }

}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[index:{}, timestamp:{}, hash:{}, prevhash:{}]", self.index, self.timestamp, self.hash, self.prevhash)
    }
}



fn main() {
    let mut blockchain: Blockchain = Blockchain::new();
    let genesis = Block::new(0, &String::from(""));
    let block2 = Block::new(1, &genesis.hash);

    blockchain.push(genesis);
    blockchain.push(block2);

    blockchain.print_all();
    //let dt = Utc::now().timestamp();// DateTime::<Utc>::from_utc(Utc::now(), Utc);
    //println!("{}", blockchain.chain[0].to_string());
}
