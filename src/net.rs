pub const NEW_BLOCK:    u8 = 0;
pub const TRANSACTION:  u8 = 1;
pub const BLOCKCHAIN:   u8 = 2;
pub const RECEIPT:      u8 = 3;

use crate::blockchain::{Blockchain, Block};
use serde::{Serialize, Deserialize};

use bincode;
#[derive(Serialize, Deserialize, Debug)]
pub struct VinoMessage {
    pub header: u8,
    pub bytes: Vec<u8>
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

    pub fn read_block(&self) -> Block {
        let block:Block = bincode::deserialize(&self.bytes).unwrap();
        block
    }

    pub fn read_blockchain(&self) -> Blockchain {
        let bc:Blockchain = bincode::deserialize(&self.bytes).unwrap();
        bc
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    pub fn from_bytes(b:&Vec<u8>) -> Result<VinoMessage, Box<bincode::ErrorKind>> {
        let me:Result<VinoMessage, Box<bincode::ErrorKind>> = bincode::deserialize(&b);
        me
    }
}