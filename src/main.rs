use sha2::{Sha256, Digest};
use chrono::Utc;
use std::fmt;

/// Represents the blockchain structure
struct Blockchain {
    chain:Vec<Block>
}

impl Blockchain {
    /// Creates a new completely empty blockchain
    fn new() -> Blockchain {
        Blockchain { chain:Vec::new() }
    }

    /// Try and push a new block to the chain
    /// Returns true if successful
    fn push(&mut self, b:Block) -> bool {
        // Attempt and get the last block of the chain
        let last_block = self.chain.last();
        match last_block {
            // Blockchain has been started
            Some(v) => {
                // Validate the new blockchain against the latest node
                let block_okay = Blockchain::validate(&v, &b);
                if block_okay {
                    // Add the new block if it checks out
                    self.chain.push(b);
                }
                block_okay
            },
            // This only happens if there is no genesis block
            None => {
                self.chain.push(b);
                true
            }
        }
    }

    /// Checks if given chain is of greater size. Replace current chain with given.
    fn replace_chain(&mut self, ch:Vec<Block>) {
        if ch.len() > self.chain.len() {
            self.chain = ch;
        }
    }

    /// Gives a rough print of the blockchain
    fn print_all(self) {
        for b in self.chain {
            println!("{}, ", b.to_string());
        }
    }

    /// Calculates a SHA256 Hash for a given block
    fn calc_hash(b:&Block) -> String {
        let mut hasher = Sha256::new();
        // Create a record string from the block
        let record = String::from(format!("{}{}{}", b.index, b.timestamp, b.prevhash));
        hasher.update(record);
        // save the hash to u8 array
        let result:[u8; 32] = hasher.finalize().into();
        // format the array into a string
        let mut fullhash = String::new();
        for x in result.iter() {
            fullhash = fullhash + &format!("{}", x);
        }
        fullhash
    }

    /// Runs some validation checks given an old block and new block.
    /// Returns true if new block is valid.
    fn validate(old_block:&Block, new_block:&Block) -> bool {
        old_block.index + 1 == new_block.index && old_block.hash == new_block.prevhash && Blockchain::calc_hash(&new_block) == new_block.hash
    }
}

/// Structure representing the data of each of Block on the chain
struct Block {
    index:      u32,
    timestamp:  String,
    hash:       String,
    prevhash:   String
}

impl Block {
    /// Creates a new block with given chain index and previous block hash.
    fn new(i:u32, prhash:&String) -> Block {
        // get current time as string
        let time = Utc::now().timestamp().to_string();
        let mut nb = Block {
            index:i,
            timestamp:time,
            prevhash:prhash.to_string(),
            hash:String::new()
        };
        // calculate a hash for this new block
        let hash = Blockchain::calc_hash(&nb);
        nb.hash = hash;
        nb
    }

}

/// Implement a to_string method for block. Used for printing info.
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
