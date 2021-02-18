mod blockchain;
use blockchain::{Blockchain, Block, Transaction, s32, s64};
use ring::signature::KeyPair;
fn main() {
    let mut blockchain: Blockchain = Blockchain::new();
    let genesis = Block::new(0, [0; 32]);
    let block2 = Block::new(1, genesis.hash);

    blockchain.push(genesis);
    blockchain.push(block2);

    blockchain.print_all();

    let key = blockchain::gen_key();
    
    
    let mut trans = Transaction::new("sender".to_string(), "recip".to_string(), 10, 1);
    trans.sign(&key);

    println!("TRANSACTION SIG: {}", s64(trans.signature));
    println!("Verified? {}", trans.verify(key.public));

    //let dt = Utc::now().timestamp();// DateTime::<Utc>::from_utc(Utc::now(), Utc);
    //println!("{}", blockchain.chain[0].to_string());
}

use std::convert::TryInto;

fn get_arr(a: &[u8]) -> [u8; 32] {
    a.try_into().expect(&format!("Slice with incorrect length! - Length: {}", a.len()))
}