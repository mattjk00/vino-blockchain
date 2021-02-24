pub const NEW_BLOCK:    u8 = 0;
pub const TRANSACTION:  u8 = 1;
pub const BLOCKCHAIN:   u8 = 2;
pub const RECEIPT:      u8 = 3;

use crate::blockchain::{Blockchain, Block, Transaction};
use serde::{Serialize, Deserialize};
use ed25519_dalek::Keypair;

use bincode;
#[derive(Serialize, Deserialize, Debug)]
pub struct VinoMessage {
    pub header: u8,
    pub bytes: Vec<u8>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonMessage<T> {
    pub header: u8,
    pub data: T
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyFile {
    pub public_bytes: [u8; 32],
    pub secret_bytes: [u8; 32]
}
impl KeyFile {
    pub fn from_keypair(kp:&Keypair) -> KeyFile {
        KeyFile {
            public_bytes:kp.public.to_bytes(),
            secret_bytes:kp.secret.to_bytes()
        }
    }
}

impl VinoMessage {
    pub fn new(hdr:u8, b:Vec<u8>) -> VinoMessage {
        VinoMessage { header:hdr, bytes: b}
    }

    pub fn new_block_message(b:&Block) -> VinoMessage {
        let bytes: Vec<u8> = bincode::serialize(&b).unwrap();
        let header = NEW_BLOCK;
        VinoMessage { header:header, bytes:bytes }
    }

    pub fn new_blockchain_message(b:&Blockchain) -> VinoMessage {
        let bytes: Vec<u8> = bincode::serialize(&b).unwrap();
        let header = BLOCKCHAIN;
        VinoMessage { header:header, bytes:bytes }
    }

    pub fn new_transaction_message(b:&Transaction) -> VinoMessage {
        let bytes: Vec<u8> = bincode::serialize(&b).unwrap();
        let header = TRANSACTION;
        VinoMessage { header:header, bytes:bytes }
    }

    pub fn read_block(&self) -> Block {
        let block:Block = bincode::deserialize(&self.bytes).unwrap();
        block
    }

    pub fn read_blockchain(&self) -> Blockchain {
        let bc:Blockchain = bincode::deserialize(&self.bytes).unwrap();
        bc
    }

    pub fn read_transaction(&self) -> Transaction {
        let t:Transaction = bincode::deserialize(&self.bytes).unwrap();
        t
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    pub fn from_bytes(b:&Vec<u8>) -> Result<VinoMessage, Box<bincode::ErrorKind>> {
        let me:Result<VinoMessage, Box<bincode::ErrorKind>> = bincode::deserialize(&b);
        me
    }

    pub fn to_json(&self) -> String {
        let s: String = serde_json::to_string(&self).unwrap();
        s
    }

}