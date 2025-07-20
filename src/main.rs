use bip39::Mnemonic;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use rand_chacha::ChaCha20Rng;
use rand::{RngCore, SeedableRng};
use bip32::XPrv;
use scrypt::{scrypt, Params as ScryptParams};
use aes::Aes128;
use ctr::Ctr32BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use uuid::Uuid;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Keystore {
    version: u32,
    id: String,
    address: String,
    crypto: Crypto,
}

#[derive(Serialize, Deserialize)]
struct Crypto {
    ciphertext: String,
    cipherparams: CipherParams,
    cipher: String,
    kdf: String,
    kdfparams: KdfParams,
    mac: String,
}

#[derive(Serialize, Deserialize)]
struct CipherParams {
    iv: String,
}

#[derive(Serialize, Deserialize)]
struct KdfParams {
    dklen: u32,
    salt: String,
    n: u32,
    r: u32,
    p: u32,
}

use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use clap::Parser;
use std::fs;
use std::path::Path;
use rpassword::prompt_password;
use std::sync::mpsc;
use std::thread;
use sha3::{Keccak256, Digest};

// Simple wallet struct using secp256k1
struct SimpleWallet {
    private_key: SecretKey,
    address: [u8; 20],
}

impl SimpleWallet {
    fn new(private_key: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        let public_key_bytes = public_key.serialize_uncompressed();
        let result = Keccak256::digest(&public_key_bytes[1..]); // Skip the prefix byte
        let mut address = [0u8; 20];
        address.copy_from_slice(&result[12..]); // Take last 20 bytes
        
        Self { private_key, address }
    }
    
    fn random(rng: &mut ChaCha20Rng) -> Self {
        let mut private_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut private_key_bytes);
        let private_key = SecretKey::from_byte_array(private_key_bytes).expect("Invalid private key");
        Self::new(private_key)
    }
    
    fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Self, Box<dyn std::error::Error>> {
        let seed = mnemonic.to_seed("");
        // Use BIP32 derivation: m/44'/60'/0'/0/0 (Ethereum standard)
        let mut xprv = XPrv::new(&seed)?;
        
        // Derive each child number in the path manually
        // m/44'/60'/0'/0/0
        xprv = xprv.derive_child(bip32::ChildNumber::new(44, true)?)?; // 44'
        xprv = xprv.derive_child(bip32::ChildNumber::new(60, true)?)?; // 60'
        xprv = xprv.derive_child(bip32::ChildNumber::new(0, true)?)?;  // 0'
        xprv = xprv.derive_child(bip32::ChildNumber::new(0, false)?)?; // 0
        xprv = xprv.derive_child(bip32::ChildNumber::new(0, false)?)?; // 0
        
        let private_key = SecretKey::from_byte_array(xprv.to_bytes())?;
        Ok(Self::new(private_key))
    }
    
    fn address(&self) -> [u8; 20] {
        self.address
    }
    
    fn to_bytes(&self) -> [u8; 32] {
        self.private_key.secret_bytes()
    }
}


#[derive(Parser, Debug)]
#[command(
    name = "genwallet",
    author = "Wallet Generator",
    version,
    about = "Generate Ethereum wallets with address pattern matching",
    long_about = "A multi-threaded Ethereum wallet generator that creates wallets with addresses matching specified patterns"
)]
struct Args {
    #[arg(short = 's', long = "start", default_value = "")]
    start_pattern: String,

    #[arg(short = 'e', long = "end", default_value = "")]
    end_pattern: String,

    #[arg(short = 'f', long = "full-key")]
    show_full_key: bool,

    #[arg(short = 'p', long = "password")]
    password: Option<String>,

    #[arg(long = "ask-password")]
    ask_password: bool,

    #[arg(short = 'o', long = "output-dir", default_value = "/tmp/generated_wallets")]
    output_dir: String,

    #[arg(short = 'n', long = "wallets", default_value = "1")]
    count: usize,

    #[arg(long = "threads")]
    threads: Option<usize>,

    #[arg(long = "show-mnemonic")]
    show_mnemonic: bool,
}

fn redact_private_key(private_key: &str) -> String {
    if private_key.len() <= 12 {
        "*".repeat(private_key.len())
    } else {
    let prefix = &private_key[..6];
    let suffix = &private_key[private_key.len() - 6..];
    format!("{}...{}", prefix, suffix)
    }
}

fn save_encrypted_wallet(
    wallet: &SimpleWallet,
    password: &str,
    output_dir: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let addr = hex_encode(&wallet.address());
    let file_path = Path::new(output_dir).join(format!("{}.json", addr));
    let private_key_bytes = wallet.to_bytes();

    // Generate random salt and IV
    let mut rng = create_hardware_rng();
    let mut salt = [0u8; 32];
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    // Derive key using scrypt (same as ethers.js)
    let mut derived_key = [0u8; 32];
    // Use exact same parameters as ethers.js: n=262144, r=8, p=1
    let scrypt_params = ScryptParams::new(18, 8, 1, 32).unwrap(); // log_n=18 means n=2^18=262144, len=32
    scrypt(password.as_bytes(), &salt, &scrypt_params, &mut derived_key).unwrap();

    // Encrypt private key using AES-128-CTR
    let mut cipher = Ctr32BE::<Aes128>::new_from_slices(&derived_key[..16], &iv).unwrap();
    let mut ciphertext = private_key_bytes;
    cipher.apply_keystream(&mut ciphertext);

    // Calculate MAC (SHA3-256 of derived_key[16..32] + ciphertext)
    let mac = Keccak256::digest([&derived_key[16..32], &ciphertext].concat());

    // Create keystore structure
    let keystore = Keystore {
        version: 3,
        id: Uuid::new_v4().to_string(),
        address: format!("0x{}", addr),
        crypto: Crypto {
            ciphertext: hex_encode(&ciphertext),
            cipherparams: CipherParams {
                iv: hex_encode(&iv),
            },
            cipher: "aes-128-ctr".to_string(),
            kdf: "scrypt".to_string(),
            kdfparams: KdfParams {
                dklen: 32,
                salt: hex_encode(&salt),
                n: 262144,
                r: 8,
                p: 1,
            },
            mac: hex_encode(&mac),
        },
    };

    // Save as JSON
    fs::write(&file_path, serde_json::to_string_pretty(&keystore)?)?;

    Ok(file_path.display().to_string())
}

fn hex_to_nybbles(hex_str: &str) -> Vec<u8> {
    hex_str
        .chars()
        .map(|c| match c.to_ascii_lowercase() {
            '0'..='9' => c as u8 - b'0',
            'a'..='f' => c as u8 - b'a' + 10,
            _ => 0,
        })
        .collect()
}

fn create_hardware_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("Failed to get hardware entropy");
    ChaCha20Rng::from_seed(seed)
}

fn hex_encode(data: &[u8]) -> String {
    // Use exact capacity for common sizes to avoid reallocations
    let capacity = match data.len() {
        16 => 32,  // IV
        20 => 40,  // Address
        32 => 64,  // Private key, salt, derived key, MAC
        64 => 128, // SHA3-256 hash
        _ => data.len() * 2, // Fallback for other sizes
    };
    let mut hex = String::with_capacity(capacity);
    for &byte in data {
        hex.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        hex.push(char::from_digit((byte & 0x0F) as u32, 16).unwrap());
    }
    hex
}

fn generate_random_password(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789";
    let mut rng = create_hardware_rng();

    let mut password = Vec::with_capacity(len);
    for _ in 0..len {
        let idx = (rng.next_u32() as usize) % CHARSET.len();
        password.push(CHARSET[idx]);
    }

    unsafe { String::from_utf8(password).unwrap_unchecked() }
}

fn match_prefix_suffix_bytes(addr: &[u8; 20], start_hex: &[u8], end_hex: &[u8]) -> bool {
    let mut addr_nybbles = [0u8; 40];
    for (i, &byte) in addr.iter().enumerate() {
        addr_nybbles[i * 2] = byte >> 4;
        addr_nybbles[i * 2 + 1] = byte & 0x0F;
    }
    addr_nybbles.starts_with(start_hex) && addr_nybbles.ends_with(end_hex)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    if args.count == 0 {
        return Err("Number of wallets must be greater than 0".into());
    }
    if args.start_pattern.len() > 40 || args.end_pattern.len() > 40 {
        return Err("Pattern length cannot exceed 40 characters".into());
    }
    
    let pattern_start = args.start_pattern.to_lowercase();
    let pattern_end = args.end_pattern.to_lowercase();
    let start_nybbles = hex_to_nybbles(&pattern_start);
    let end_nybbles = hex_to_nybbles(&pattern_end);

    let pattern_difficulty = if !pattern_start.is_empty() && !pattern_end.is_empty() {
        16.0_f64.powi((pattern_start.len() + pattern_end.len()) as i32)
    } else if !pattern_start.is_empty() {
        16.0_f64.powi(pattern_start.len() as i32)
    } else if !pattern_end.is_empty() {
        16.0_f64.powi(pattern_end.len() as i32)
    } else {
        1.0
    };

    let thread_count = args.threads.unwrap_or_else(|| {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });

    let password = if let Some(pw) = args.password {
        pw
    } else if args.ask_password {
        prompt_password("Enter password to encrypt wallets: ")?
    } else {
        let random_password = generate_random_password(16);
        println!("Generated random password: {}", random_password);
        random_password
    };

    println!(
        "Searching for {} wallet(s) with address starting with '{}' and ending with '{}' using {} threads",
        args.count, pattern_start, pattern_end, thread_count
    );

    let found_count = Arc::new(AtomicUsize::new(0));
    let total_attempts = Arc::new(AtomicU64::new(0));
    let (sender, receiver) = mpsc::channel();
    let start_time = Instant::now();
    let progress_interval = if args.show_mnemonic { 10_000 } else { 100_000 };

    // Create seeds once using hardware entropy
    let mut master_rng = create_hardware_rng();
    let seeds: Vec<[u8; 32]> = (0..thread_count)
        .map(|_| {
            let mut seed = [0u8; 32];
            master_rng.fill_bytes(&mut seed);
            seed
        })
        .collect();

    // Create threads manually instead of using rayon
    let mut handles = Vec::new();
    for (_i, seed) in seeds.into_iter().enumerate() {
        let sender = sender.clone();
        let total_attempts = total_attempts.clone();
        let found_count = found_count.clone();
        let start_nybbles = start_nybbles.clone();
        let end_nybbles = end_nybbles.clone();
        let args_count = args.count;
        let args_show_mnemonic = args.show_mnemonic;
        let password = password.clone();
        let output_dir = args.output_dir.clone();
        let args_show_full_key = args.show_full_key;
        let _args_show_mnemonic = args.show_mnemonic;
        let pattern_difficulty = pattern_difficulty;
        
        let handle = thread::spawn(move || {
            let mut rng = ChaCha20Rng::from_seed(seed);

            while found_count.load(Ordering::Acquire) < args_count {
                let (wallet, mnemonic) = if args_show_mnemonic {
                    // Mnemonic path - generate entropy and create wallet from mnemonic
                    let mut entropy = [0u8; 16];
                    rng.fill_bytes(&mut entropy);

                    let mnemonic = match Mnemonic::from_entropy(&entropy) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };

                    let wallet = match SimpleWallet::from_mnemonic(&mnemonic) {
                        Ok(w) => w,
                        Err(_) => continue,
                    };

                    (wallet, Some(mnemonic))
                } else {
                    // Fast path - direct wallet generation
                    (SimpleWallet::random(&mut rng), None)
                };

                let addr_bytes = wallet.address();
            
                // Update attempt count
                let current_attempts = total_attempts.fetch_add(1, Ordering::Relaxed);
                if current_attempts % progress_interval == 0 {
                    let elapsed = start_time.elapsed();
                    let rate = current_attempts as f64 / elapsed.as_secs_f64();
                    let found = found_count.load(Ordering::Relaxed);

                    let remaining_wallets = args_count.saturating_sub(found);
                    let eta_seconds = if rate > 0.0 && remaining_wallets > 0 && found > 0 {
                        let attempts_per_wallet = current_attempts as f64 / found as f64;
                        let remaining_attempts = attempts_per_wallet * remaining_wallets as f64;
                        remaining_attempts / rate
                    } else if rate > 0.0 && remaining_wallets > 0 {
                        let estimated_attempts_per_wallet = pattern_difficulty;
                        let remaining_attempts = estimated_attempts_per_wallet * remaining_wallets as f64;
                        remaining_attempts / rate
                    } else {
                        0.0
                    };

                    let eta_str = if eta_seconds > 0.0 {
                        if eta_seconds < 60.0 {
                            format!("{:.0}s", eta_seconds)
                        } else if eta_seconds < 3600.0 {
                            format!("{:.0}m", eta_seconds / 60.0)
                        } else {
                            format!("{:.1}h", eta_seconds / 3600.0)
                        }
                    } else {
                        "∞".to_string()
                    };

                    print!(
                        "\rAttempts: {}M, Found: {}/{}, Rate: {:.0}K/s, ETA: {}",
                        current_attempts / 1_000_000,
                        found,
                        args_count,
                        rate / 1_000.0,
                        eta_str
                    );
                }

                if match_prefix_suffix_bytes(&addr_bytes, &start_nybbles, &end_nybbles) {
                    let addr_hex = hex_encode(&addr_bytes);
                    let private_key_bytes = wallet.to_bytes();

                    let idx = found_count.fetch_add(1, Ordering::AcqRel);
                    if idx < args_count {
                        match save_encrypted_wallet(&wallet, &password, &output_dir) {
                            Ok(path) => {
                                println!("\n🎉 Found wallet {} of {}", idx + 1, args_count);
                                println!("Address:    0x{}", addr_hex);
                                if args_show_full_key {
                                    println!("PrivateKey: {}", hex_encode(&private_key_bytes));
                                } else {
                                    println!(
                                        "PrivateKey: {}",
                                        redact_private_key(&hex_encode(&private_key_bytes))
                                    );
                                }
                                if args_show_mnemonic {
                                    // Display the stored mnemonic
                                    if let Some(m) = mnemonic {
                                        println!("Mnemonic:   {}", m.to_string());
                                    }
                                }
                                println!("Saved to:   {}", path);
                                println!("---");

                                sender.send((addr_hex, hex_encode(&private_key_bytes), path))
                                    .ok();
                            }
                            Err(e) => {
                                eprintln!("Error saving encrypted wallet: {}", e);
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    let mut final_results = Vec::new();
    for _ in 0..args.count {
        if let Ok((addr, pk_hex, path)) = receiver.recv() {
            final_results.push((addr, pk_hex, path));
        }
    }

    let elapsed = start_time.elapsed();
    let total_attempts = total_attempts.load(Ordering::Relaxed);
    let rate = total_attempts as f64 / elapsed.as_secs_f64();

    println!("\n=== Summary ===");
    println!("Generated {} wallet(s) successfully", final_results.len());
    println!("Total attempts: {}M", total_attempts / 1_000_000);
    println!("Average rate: {:.0}K attempts/second", rate / 1_000.0);
    if args.count > 1 {
        println!("All wallets saved to: {}", args.output_dir);
    }
    println!("\nTotal time: {:.2?}", elapsed);

    Ok(())
}
