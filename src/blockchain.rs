use sha2::{Sha256, Digest};
use std::fmt;
use chrono::Utc;

extern crate rand;
extern crate ed25519_dalek;
use rand::rngs::OsRng;
use ed25519_dalek::{Keypair, Signer, Signature, PublicKey, Verifier};

/// Represents the blockchain structure
pub struct Blockchain {
    chain:Vec<Block>
}

impl Blockchain {
    /// Creates a new completely empty blockchain
    pub fn new() -> Blockchain {
        Blockchain { chain:Vec::new() }
    }

    /// Try and push a new block to the chain
    /// Returns true if successful
    pub fn push(&mut self, b:Block) -> bool {
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
    pub fn replace_chain(&mut self, ch:Vec<Block>) {
        if ch.len() > self.chain.len() {
            self.chain = ch;
        }
    }

    /// Gives a rough print of the blockchain
    pub fn print_all(self) {
        for b in self.chain {
            println!("{}, ", b.to_string());
        }
    }

    /// Calculates a SHA256 Hash for a given block
    fn calc_hash(b:&Block) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Create a record string from the block
        let record = String::from(format!("{}{}{}", b.index, b.timestamp, s32(b.prevhash)));
        hasher.update(record);
        // save the hash to u8 array
        let result:[u8; 32] = hasher.finalize().into();
        result
    }

    /// Runs some validation checks given an old block and new block.
    /// Returns true if new block is valid.
    fn validate(old_block:&Block, new_block:&Block) -> bool {
        old_block.index + 1 == new_block.index && old_block.hash == new_block.prevhash && Blockchain::calc_hash(&new_block) == new_block.hash
    }
}

/// Converts a length 32 byte array to a string representation
pub fn s32(a:[u8; 32]) -> String {
    let mut s = String::new();
    for x in a.iter() {
        s = s + &format!("{}", x);
    }
    s
}

/// Converts a length 32 byte array to a string representation
pub fn s64(a:[u8; 64]) -> String {
    let mut s = String::new();
    for x in a.iter() {
        s = s + &format!("{}", x);
    }
    s
}

/// Structure representing the data of each of Block on the chain
pub struct Block {
    index:          u32,
    pub timestamp:  String,
    pub hash:       [u8; 32],
    prevhash:       [u8; 32],
    nonce:          u32,
    transactions:   Vec<Transaction>
}

impl Block {
    /// Creates a new block with given chain index and previous block hash.
    pub fn new(i:u32, prhash_bytes:[u8; 32]) -> Block {
        // get current time as string
        let time = Utc::now().timestamp().to_string();
        let mut nb = Block {
            index:i,
            timestamp:time,
            //prevhash:prhash.to_string(),
            //hash:String::new(),
            nonce: 0,
            transactions:Vec::new(),
            hash:[0;32],
            prevhash:prhash_bytes
        };
        // calculate a hash for this new block
        nb.hash = Blockchain::calc_hash(&nb);
        nb
    }

    pub fn add_transaction(&mut self, t:Transaction) {
        self.transactions.push(t);
    }
}

/// Implement a to_string method for block. Used for printing info.
impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[index:{}, timestamp:{}, hash:{}, prevhash:{}]", self.index, self.timestamp, s32(self.hash), s32(self.prevhash))
    }
}

pub struct Transaction {
    pub signature:  [u8; 64],
    blockhash:      [u8; 32],
    input:          String,
    output:         String,
    value:          u32,
    fee:            u32
}

impl Transaction {
    pub fn new(inp:String, out:String, val:u32, fee:u32) -> Transaction {
        Transaction { signature:[0; 64], blockhash:[0; 32], input:inp, output:out, value:val, fee: fee }
    }

    pub fn sign(&mut self, kp:&Keypair) {
        let record_str = self.form_record();
        let record = record_str.as_bytes();
        let sig = kp.sign(record);
        self.signature = sig.to_bytes();
    }

    fn form_record(&self) -> String {
        format!("{}{}{}{}", self.input, self.output, self.value, self.fee)
    }

    pub fn verify(self, pkey:PublicKey) -> bool {
        let csig = Signature::new(self.signature);
        let result = pkey.verify(self.form_record().as_bytes(), &csig).is_ok();
        result
    }
}

pub fn gen_key() -> Keypair {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    keypair
}