use sha2::{Sha256, Digest};
use std::fmt;
use chrono::Utc;
use serde::{Serialize, Deserialize};
use bincode;
extern crate rand;
extern crate ed25519_dalek;
use rand::rngs::OsRng;
use ed25519_dalek::{Keypair, Signer, Signature, PublicKey, Verifier};
const REWARD:f32 = 5.0;
const PROOF_C:usize = 2; // number of leading zero's required on hash

/// Represents the blockchain structure
#[derive(Serialize, Deserialize, Debug)]
pub struct Blockchain {
    pub chain:Vec<Block>
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
                let block_okay = self.validate(&v, &b);
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
    pub fn replace_chain(&mut self, ch:Vec<Block>) -> bool {
        if ch.len() > self.chain.len() {
            self.chain = ch;
            return true;
        }
        false
    }

    /// Gives a rough print of the blockchain
    pub fn print_all(&self) {
        for b in self.chain.iter() {
            println!("{}, ", b.to_string());
        }
    }

    /// Calculates a SHA256 Hash for a given block
    pub fn calc_hash(b:&Block) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Create a record string from the block
        let record = String::from(format!("{}{}{}{}", b.index, b.timestamp, s32(b.prevhash), b.nonce));
        hasher.update(record);
        // save the hash to u8 array
        let result:[u8; 32] = hasher.finalize().into();
        result
    }

    /// Runs some validation checks given an old block and new block.
    /// Returns true if new block is valid.
    /// A block's hash and all its transactions must be valid to return true
    fn validate(&self, old_block:&Block, new_block:&Block) -> bool {
        // some checks on the block itself
        let block_okay = old_block.index + 1 == new_block.index && old_block.hash == new_block.prevhash && Blockchain::calc_hash(&new_block) == new_block.hash && Blockchain::has_proof_of_work(new_block.hash);
        let mut transactions_okay = true;
        
        // check each transaction in the block
        for t in new_block.transactions.iter() {
            // parse the public key out from the block
            let public_key = PublicKey::from_bytes(&t.public_key);
            match public_key {
                // check the key is okay
                Ok(pk) => { 
                    // validate the transaction with this key
                    let t_result = self.validate_transaction(&t,pk);
                    // if any transaction is bad, stop checking
                    if t_result == false {
                        transactions_okay = false;
                        break;
                    }
                },
                // Handle malfunction
                Err(_e) => {
                    println!("BAD: {}", s32(t.public_key));
                }
            }    
        }
        block_okay && transactions_okay
    }

    /// Validates a single given transaction with given public key
    /// Checks for valid signature and if coins are sendable
    fn validate_transaction(&self, t:&Transaction, pkey:PublicKey) -> bool {
        let csig = Signature::new(t.signature());
        // verify signature
        let sig_result = pkey.verify(t.form_record().as_bytes(), &csig).is_ok();
        // determine probable value of sender's coins --- the will be ignored if coins are being sent by the genesis block
        let sender_value = self.determine_value(t.input);
        sig_result && (sender_value >= t.value || t.input == self.genesis_hash().unwrap())
    }

    /// Function to try and determine the value in coins of a single address
    pub fn determine_value(&self, address:[u8; 32]) -> f32 {
        let mut sum:f32 = 0.0;
        for b in self.chain.iter() {
            for t in b.transactions.iter() {
                // checking for when the address is a recipient
                if t.output == address {
                    sum += t.value;
                }
                // checking for when the address is a sender
                // value will not go negative because that can not exist on the blockchain.
                if t.input == address {
                    if sum >= t.value {
                        sum -= t.value;
                    } else {
                        return 0.0;
                    }
                    
                }
            }
        }
        sum
    }

    /// Tries to get the hash from the last block on the chain
    pub fn last_hash(&self) -> Option<[u8; 32]> {
        match self.chain.len() > 0 {
            true => Some(self.chain[self.chain.len() - 1].hash),
            false => None
        }
    }

    /// Tries to get the genesis hash from the blockchain.
    pub fn genesis_hash(&self) -> Option<[u8; 32]> {
        match self.chain.len() > 0 {
            true => Some(self.chain[0].hash),
            false => None
        }
    }

    /// Determines if a given hash has sufficient proof of work in the hash.
    pub fn has_proof_of_work(hash:[u8; 32]) -> bool {
        let mut proof = true;
        for i in 0..PROOF_C {
            if hash[i] != 0 {
                proof = false;
            }
        }
        proof
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

pub fn s32_format(a:[u8; 32], delimiter:String) -> String {
    let mut s = String::new();
    for x in a.iter() {
        s = s + &format!("{}{}", x, delimiter);
    }
    s
}

/// Converts a length 64 byte array to a string representation
pub fn s64(a:[u8; 64]) -> String {
    let mut s = String::new();
    for x in a.iter() {
        s = s + &format!("{}", x);
    }
    s
}

/// Converts a dash delimited string representation of a byte array and parses it back into a byte array
pub fn b32(a:&String) -> [u8; 32] {
    let mut arr = [0; 32];
    let mut split = a.split("-").collect::<Vec<_>>();
    for i in 0..32 {
        let sb = split[i].as_bytes();
        let mut sum:u8 = 0;
        for j in (0..sb.len()).rev() {
            let scale = (10u8.pow((sb.len() - j - 1) as u32));
            let value:u8 = (sb[j] - 48) * scale;
            sum += value;
        }
        arr[i] = sum;
    }
    arr
}

/// Structure representing the data of each of Block on the chain
#[derive(Serialize, Deserialize, Debug)]
pub struct Block {
    index:              u32,
    pub timestamp:      String,
    pub hash:           [u8; 32],
    prevhash:           [u8; 32],
    pub nonce:          u32,
    pub transactions:   Vec<Transaction>
}

impl Block {
    /// Creates a new block with given chain index and previous block hash.
    pub fn new(i:u32, prhash_bytes:[u8; 32]) -> Block {
        // get current time as string
        let time = Utc::now().timestamp().to_string();
        let mut nb = Block {
            index:i,
            timestamp:time,
            nonce: 0,
            transactions:Vec::new(),
            hash:[0;32],
            prevhash:prhash_bytes
        };
        // calculate a hash for this new block
        nb.hash = Blockchain::calc_hash(&nb);
        nb
    }

    /// Adds a transaction. Does not validate it.
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

/// Represents a transaction on the blockchain.
#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction {
    signature_first:  [u8; 32],
    signature_second: [u8; 32],
    blockhash:      [u8; 32],
    input:          [u8; 32],
    output:         [u8; 32],
    value:          f32,
    fee:            f32,
    public_key:     [u8; 32]
}

impl Transaction {
    /// Create an unsigned transaction with input, output, value, and fee attached
    pub fn new(inp:[u8; 32], out:[u8; 32], val:f32, fee:f32) -> Transaction {
        Transaction { signature_first:[0; 32], signature_second:[0; 32], blockhash:[0; 32], input:inp, output:out, value:val, fee: fee, public_key:inp }
    }

    /// Creates a reward transaction. Used to reward miners on the blockchain. The input will be from the genesis hash.
    pub fn new_reward(genesis_hash:[u8; 32], blockhash:[u8; 32], dest:[u8; 32]) -> Transaction {
        Transaction { signature_first:[0; 32], signature_second:[0; 32], blockhash:blockhash, input:genesis_hash, output:dest, value:REWARD, fee:0.0, public_key:dest }
    }

    /// Signs the transaction with given keys
    pub fn sign(&mut self, kp:&Keypair) {
        let record_str = self.form_record();
        let record = record_str.as_bytes();
        let sig = kp.sign(record);
        //self.signature = sig.to_bytes();
        let sigb = sig.to_bytes();
        self.signature_first = get_arr(&sigb[..32]);
        self.signature_second = get_arr(&sigb[32..]);
    }

    /// Returns the string record format of the transaction. What gets crypto'd
    fn form_record(&self) -> String {
        format!("{}{}{}{}", s32(self.input), s32(self.output), self.value, self.fee)
    }

    fn signature(&self) -> [u8; 64] {
        let mut sig = [0; 64];
        for i in 0..self.signature_first.len() {
            sig[i] = self.signature_first[i];
        }
        for i in 0..self.signature_second.len() {
            sig[i + 32] = self.signature_second[i];
        }
        sig
    }
}

/// Implement a to_string method for block. Used for printing info.
impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[\tfrom:{}\n\tto:{}\n\tblockhash:{}\n\tsignature:{}{}\n]", s32(self.input), s32(self.output), s32(self.blockhash), s32(self.signature_first), s32(self.signature_second))
    }
}

/// Utility function for generating pub/secret keys
pub fn gen_key() -> Keypair {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    keypair
}

use std::convert::TryInto;
fn get_arr(a: &[u8]) -> [u8; 32] {
    a.try_into().expect(&format!("Slice with incorrect length! - Length: {}", a.len()))
}