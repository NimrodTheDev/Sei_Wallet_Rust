use std::str::FromStr;
use bech32::{encode, ToBase32, Variant};
use bip39::{Mnemonic};
use hdkey::HDKey;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::{Sha256, Digest};
use std::env;
use ripemd::{Ripemd160};

fn main() {
    // let entropy  = [rand::thread_rng().gen(); 32];
    let arg:Vec<String> = env::args().collect();
    println!("test: {} ```", arg[0].to_string());
    let mnemonic = Mnemonic::from_str(&arg[1].to_string()).unwrap();
    // let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    println!("Mnemonic {}", mnemonic.to_string());
    let seed = mnemonic.to_seed("".to_string());
    let master_key = HDKey::from_master_seed(&seed, None).unwrap();
    let derived_key = master_key.derive("m/44'/118'/0'/0/0").unwrap();
    
    let secp = Secp256k1::new();
    
    let secret_key = SecretKey::from_slice(
        &derived_key.private_key().unwrap()
        // &seed[0..32]
    ).unwrap();
    let pub_key = PublicKey::from_secret_key(&secp, &secret_key);
    println!("Pub_Key 1 {:?}", pub_key.serialize());


    let mut hasher = Sha256::new();
    hasher.update(&pub_key.serialize());
    let sha256_hash = hasher.finalize();
    

    // Step 2: Apply RIPEMD-160 hashing
    let mut ripemd160_hasher = Ripemd160::new();
    ripemd160_hasher.update(&sha256_hash);
    let ripemd160_hash = ripemd160_hasher.finalize();


    let address = encode("sei", ripemd160_hash.to_base32(), Variant::Bech32).unwrap();

    println!("Address {}", address);
    println!("Pub_Key {:?}", sha256_hash);
}