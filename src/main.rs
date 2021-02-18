mod blockchain;
use blockchain::{Blockchain, Block, Transaction, s32, s64};
mod miner;
use ring::signature::KeyPair;
fn main() {
    println!("--- VINO COIN ---");
    let mut blockchain: Blockchain = Blockchain::new();
    let genesis = Block::new(0, [0; 32]);
    let mut block2 = Block::new(1, genesis.hash);

    
    

    let key = blockchain::gen_key();
    let friend_key = blockchain::gen_key();
    
    let mut miner = miner::Miner::new(block2);
    println!("Mining...");
    while miner.is_done() == false {
        miner.mine();
    }
    let mut block2 = miner.target;
    
    let mut reward = Transaction::new_reward(genesis.hash, block2.hash, key.public.to_bytes());
    reward.sign(&key);

    blockchain.push(genesis);
    block2.add_transaction(reward);
    blockchain.push(block2);

    //println!("Verified? {}", blockchain.chain[1].transactions[0].verify(key.public));
    blockchain.print_all();

    let mut block3 = Block::new(2, blockchain.last_hash().unwrap());

    let mut send_to_friend = Transaction::new(key.public.to_bytes(), friend_key.public.to_bytes(), 4, 0);
    send_to_friend.sign(&key);
    block3.add_transaction(send_to_friend);

    println!("Mining...");
    miner = miner::Miner::new(block3);
    while miner.is_done() == false {
        miner.mine();
    }
    let mut block3 = miner.target;
    blockchain.push(block3);


    let value = blockchain.determine_value(key.public.to_bytes());
    let fvalue = blockchain.determine_value(friend_key.public.to_bytes());
    println!("Your Wallet: {} coins.", value);
    println!("Friend's Wallet: {} coins.", fvalue);

    
    //println!("TRANSACTION SIG: {}", s64(trans.signature));
    

    //let dt = Utc::now().timestamp();// DateTime::<Utc>::from_utc(Utc::now(), Utc);
    //println!("{}", blockchain.chain[0].to_string());
}

use std::convert::TryInto;

fn get_arr(a: &[u8]) -> [u8; 32] {
    a.try_into().expect(&format!("Slice with incorrect length! - Length: {}", a.len()))
}