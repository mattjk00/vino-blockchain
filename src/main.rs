mod blockchain;
use blockchain::{Blockchain, Block, Transaction, s32, s64, s32_format, b32};
use net::VinoMessage;
mod miner;
mod net;
use net::*;
use ring::signature::KeyPair;
use async_std::{io, task};
use futures::{future, prelude::*};
use libp2p::{
    Multiaddr,
    PeerId,
    Swarm,
    NetworkBehaviour,
    identity,
    floodsub::{self, Floodsub, FloodsubEvent},
    mdns::{Mdns, MdnsEvent},
    swarm::NetworkBehaviourEventProcess
};
use std::{thread, error::Error, task::{Context, Poll}, fs::File, io::prelude::*, io::{BufReader, ErrorKind}, sync::Mutex};
use bincode;
use serde_json;
use ed25519_dalek::{Keypair, Signer, Signature, PublicKey, SecretKey, Verifier};
//use libp2p::futures::StreamExt;

use actix_web::{web, App, HttpRequest, HttpServer, Responder};

struct AppState {
    blockchain:Mutex<Blockchain>
}


async fn greet(req: HttpRequest) -> impl Responder {
    let name = req.match_info().get("name").unwrap_or("World");
    format!("Hello {}!", &name)
}

async fn get_public_key(req: HttpRequest) -> impl Responder {
    format!("123-456-78-90")
}

async fn get_blockchain(data: web::Data<AppState>) -> String {
    let mut bc = data.blockchain.lock().unwrap();

    let b_msg = serde_json::to_string(&*bc).unwrap();

    println!("{}", b_msg);
    format!("{}", b_msg)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let state = web::Data::new(AppState {
        blockchain:Mutex::new(Blockchain::new())
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/pubkey", web::get().to(get_public_key))
            .route("/blockchain", web::get().to(get_blockchain))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

/*
fn main() -> Result<(), Box<dyn Error>> {
    println!("--- VINO COIN ---");

    


    //env_logger::init();
    // Create a random PeerId
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

    // Set up a an encrypted DNS-enabled TCP Transport over the Mplex and Yamux protocols
    let transport = libp2p::build_development_transport(local_key)?;

    // Create a Floodsub topic
    let floodsub_topic = floodsub::Topic::new("vino-bc");

    // We create a custom network behaviour that combines floodsub and mDNS.
    // In the future, we want to improve libp2p to make this easier to do.
    // Use the derive to generate delegating NetworkBehaviour impl and require the
    // NetworkBehaviourEventProcess implementations below.
    #[derive(NetworkBehaviour)]
    struct MyBehaviour {
        floodsub: Floodsub,
        mdns: Mdns,
        #[behaviour(ignore)]
        blockchain:Blockchain,
        #[behaviour(ignore)]
        received_transactions:Vec<Transaction>,

        // Struct fields which do not implement NetworkBehaviour need to be ignored
        #[behaviour(ignore)]
        #[allow(dead_code)]
        ignored_member: bool,
    }

    impl NetworkBehaviourEventProcess<FloodsubEvent> for MyBehaviour {
        // Called when `floodsub` produces an event.
        fn inject_event(&mut self, message: FloodsubEvent) {
            if let FloodsubEvent::Message(message) = message {
                let vmsg = VinoMessage::from_bytes(&message.data);
                match vmsg {
                    Ok(m) => {
                        if m.header == net::NEW_BLOCK {
                            let block = m.read_block();

                            /*for i in 0..self.received_transactions.len() {
                                if block.has_transaction(&self.received_transactions[i]) {
                                    self.received_transactions.remove(i);
                                }
                            }*/

                            let valid = self.blockchain.push(block);
                            println!("New Block | Valid: {} | '{:?}' from {:?}", valid, s32(self.blockchain.last_hash().unwrap()), message.source);

                            
                        }
                        if m.header == net::BLOCKCHAIN {
                            let bc = m.read_blockchain();
                            let replaced = self.blockchain.replace_chain(bc.chain);
                            println!("Replaced? {}", replaced);
                        }
                        if m.header == net::TRANSACTION {
                            let transaction = m.read_transaction();
                            println!("TRANSACTION: {}", transaction.value);
                            let valid = self.blockchain.validate_transaction(&transaction, &ed25519_dalek::PublicKey::from_bytes(&transaction.public_key).unwrap());
                            if valid {
                                self.received_transactions.push(transaction);
                            }
                        }
                    },
                    Err(_e) => { println!("ignored. "); }
                };
                
            }
        }
    }

    impl NetworkBehaviourEventProcess<MdnsEvent> for MyBehaviour {
        // Called when `mdns` produces an event.
        fn inject_event(&mut self, event: MdnsEvent) {
            match event {
                MdnsEvent::Discovered(list) =>
                    for (peer, _) in list {
                        self.floodsub.add_node_to_partial_view(peer);
                    }
                MdnsEvent::Expired(list) =>
                    for (peer, _) in list {
                        if !self.mdns.has_node(&peer) {
                            self.floodsub.remove_node_from_partial_view(&peer);
                        }
                    }
            }
        }
    }

    // Create a Swarm to manage peers and events
    let mut swarm = {
        let mdns = task::block_on(Mdns::new())?;
        let mut behaviour = MyBehaviour {
            floodsub: Floodsub::new(local_peer_id.clone()),
            mdns,
            ignored_member: false,
            blockchain:Blockchain::new(),
            received_transactions:Vec::new()
        };

        let genesis = Block::new(0, [0; 32]);
        behaviour.blockchain.push(genesis);

        behaviour.floodsub.subscribe(floodsub_topic.clone());
        Swarm::new(transport, behaviour, local_peer_id)
    };

    // Reach out to another node if specified
    if let Some(to_dial) = std::env::args().nth(1) {
        let addr: Multiaddr = to_dial.parse()?;
        Swarm::dial_addr(&mut swarm, addr)?;
        println!("Dialed {:?}", to_dial)
    }

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/0".parse()?)?;

    // Kick it off
    let mut listening = false;
    let mut cmd_mode:String = String::new();
    let mut cmd_params:Vec<String> = Vec::new();
    let mut key = blockchain::gen_key();

    //let mut minerrr = miner::Miner::new(Block::new(0, [0;32]));
    let mut is_mining = false;
    

    task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
        loop {
            match stdin.try_poll_next_unpin(cx)? {
                Poll::Ready(Some(line)) => { 
                    /*if line == "gen" {
                        let genesis = Block::new(0, [0; 32]);
                        let msg = VinoMessage::new_block_message(&genesis);
                        swarm.floodsub.publish(floodsub_topic.clone(), &msg.to_bytes()[..])
                    }*/

                    if cmd_mode == "t" {
                        cmd_params.push(line);
                        if cmd_params.len() == 1 {
                            println!("Enter amount:");
                        } else if cmd_params.len() == 2 {
                            println!("Sending...");
                            cmd_mode = "".to_string();

                            let recip = b32(&cmd_params[0]);
                            let val:f32 = cmd_params[1].parse().unwrap();
                            let mut ts = Transaction::new(key.public.to_bytes(), recip, val, 0.0);
                            ts.sign(&key);
                            let tmsg = VinoMessage::new_transaction_message(&ts);
                            swarm.received_transactions.push(ts);
                            swarm.floodsub.publish(floodsub_topic.clone(), &tmsg.to_bytes()[..]);
                        }
                    }
                    else {
                        if line == "bc" {
                            let a = &swarm.blockchain;
                            let msg = VinoMessage::new_blockchain_message(a);
                            swarm.floodsub.publish(floodsub_topic.clone(), &msg.to_bytes()[..]);
                            println!("Broadcasting blockchain...");
                        } 
                        else if line == "t" {
                            cmd_mode = "t".to_string();
                            cmd_params.clear();
                            println!("Enter recipient:");
                        }
                        else if line == "keys" {
                            let out = s32_format(key.public.to_bytes(), "-".to_string());
                            println!("Public: {}", out);
                        }
                        else if line == "mine" {

                            
                            let mut mineblock = Block::new(swarm.blockchain.chain.len() as u32, swarm.blockchain.last_hash().unwrap());
                            let mut miner = miner::Miner::new(mineblock);
                            println!("Mining...");
                            while miner.is_done() == false {
                                miner.mine();
                            }
                            println!("Done.");
                            
                            
                            let mut block = miner.target;
                            let mut reward = Transaction::new_reward(swarm.blockchain.genesis_hash().unwrap(), block.hash, key.public.to_bytes());
                            reward.sign(&key);
                            block.add_transaction(reward);

                            while swarm.received_transactions.len() > 0 {
                                println!("{}", swarm.received_transactions.last().unwrap().value);
                                block.add_transaction(swarm.received_transactions.pop().unwrap());
                                println!("Ts: {}", block.transactions.len());
                            }
                            
                            let msg = VinoMessage::new_block_message(&block);
                            swarm.blockchain.push(block);
                            swarm.floodsub.publish(floodsub_topic.clone(), &msg.to_bytes()[..])
                        }
                        else if line == "bal" {
                            let balance = swarm.blockchain.determine_value(key.public.to_bytes());
                            println!("Balance: {}", balance);
                        }
                        else if line == "see" {
                            swarm.blockchain.print_all();
                        }
                        else if line == "save" {
                            println!("Saving...");
                            save_bc_to_file(&swarm.blockchain);
                        }
                        else if line == "load" {
                            println!("Loading...");
                            match read_bc_from_file("bc.vn".to_string()) {
                                Ok(bc) => {
                                    swarm.blockchain = bc;
                                    println!("Loaded {} block!", swarm.blockchain.chain.len());
                                },
                                Err(e) => {}
                            };
                        }
                        else if line.contains("save_keys") {
                            let cmds = match line.contains(" ") {
                                true => line.split(' ').collect::<Vec<&str>>(),
                                false => vec!["", "keys.vn"]
                            };
                            let path = cmds[1];
                            println!("Saving Keys...");
                            match save_keys_to_file(&net::KeyFile::from_keypair(&key), path.to_string()) {
                                Ok(()) => { println!("Saved!"); },
                                Err(e) => { println!("Error! Could not save -- {}", e); }
                            }
                        }
                        else if line.contains("load_keys") {
                            let cmds = match line.contains(" ") {
                                true => line.split(' ').collect::<Vec<&str>>(),
                                false => vec!["", "keys.vn"]
                            };
                            let path = cmds[1];
                            println!("Loading Keys...");
                            match read_keys_from_file(path.to_string()) {
                                Ok(ks) => {
                                    key = ks;
                                    println!("Loaded Keys.");
                                },
                                Err(e) => {}
                            }
                        }
                        else {
                            swarm.floodsub.publish(floodsub_topic.clone(), "Hi.".as_bytes());
                            println!("Unknown command: {}", line);
                        }
                        
                    }
                    print!("{}[2J", 27 as char);
                    //print!("\x1B[2J\x1B[1;1H");
                    //last_msg = line;
                },
                Poll::Ready(None) => panic!("Stdin closed"),
                Poll::Pending => break
            }
        }
        loop {
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => println!("Event{:?}", event),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => {
                    if !listening {
                        for addr in Swarm::listeners(&swarm) {
                            println!("Listening on {:?}", addr);
                            listening = true;
                        }
                    }
                    break
                }
            }
        }
        Poll::Pending
    }))

    
    /*let mut blockchain: Blockchain = Blockchain::new();
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
    println!("Friend's Wallet: {} coins.", fvalue);*/


    //println!("TRANSACTION SIG: {}", s64(trans.signature));


    //let dt = Utc::now().timestamp();// DateTime::<Utc>::from_utc(Utc::now(), Utc);
    //println!("{}", blockchain.chain[0].to_string());
}
*/
use std::convert::TryInto;


fn save_bc_to_file(b:&Blockchain) -> std::io::Result<()> {
    let mut file = File::create("bc.vn")?;
    file.write_all(&serde_json::to_string(&b)?.as_bytes());
    Ok(())
}

fn read_bc_from_file(path:String) -> std::io::Result<Blockchain> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let bc = serde_json::from_str(&contents)?;
    Ok(bc)
}

fn save_keys_to_file(k:&net::KeyFile, path:String) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(&serde_json::to_string(&k)?.as_bytes())?;
    Ok(())
}

fn read_keys_from_file(path:String) -> std::io::Result<Keypair> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let keyfile:net::KeyFile = serde_json::from_str(&contents)?;
    let try_pbytes = PublicKey::from_bytes(&keyfile.public_bytes);

    match try_pbytes  {
        Ok(pk) => {
            match SecretKey::from_bytes(&keyfile.secret_bytes) {
                Ok(sk) => {
                    Ok(Keypair {
                        public:pk,
                        secret:sk
                    })
                },
                Err(e) => Err(std::io::Error::new(ErrorKind::InvalidData, "Invalid Secret Key."))
            }
        },
        Err(e) => Err(std::io::Error::new(ErrorKind::InvalidData, "Invalid Public Key."))
    }

    
    
}