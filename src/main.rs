use bip39::Mnemonic;
use secp256k1::{Secp256k1, SecretKey, PublicKey, Scalar};
use rand_chacha::ChaCha20Rng;
use rand::{RngCore, SeedableRng};
use bip32::XPrv;
use scrypt::{scrypt, Params as ScryptParams};
use aes::Aes128;
use ctr::Ctr32BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use serde::{Serialize, Deserialize};
use std::sync::LazyLock;

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
    #[inline]
    fn new(private_key: SecretKey) -> Self {
        static SECP256K1: LazyLock<Secp256k1<secp256k1::All>> = 
            LazyLock::new(Secp256k1::new);
        
        let public_key = PublicKey::from_secret_key(&SECP256K1, &private_key);
        let pub_bytes = public_key.serialize_uncompressed();

        let mut hasher = Keccak256::new();
        hasher.update(&pub_bytes[1..]);
        let hash = hasher.finalize();

        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        
        Self { private_key, address }
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
    
    #[inline]
    fn address(&self) -> [u8; 20] {
        self.address
    }
    
    #[inline]
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
    // Use chain() instead of concat() to avoid allocation
    let mut mac_hasher = Keccak256::new();
    mac_hasher.update(&derived_key[16..32]);
    mac_hasher.update(&ciphertext);
    let mac = mac_hasher.finalize();

    // Generate unique ID: timestamp + random
    let id = format!("{:x}-{:x}", 
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        rng.next_u64()
    );

    // Create keystore structure
    let keystore = Keystore {
        version: 3,
        id,
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

#[inline]
fn hex_to_nybbles(hex_str: &str) -> Vec<u8> {
    // Pre-allocate with exact capacity to avoid reallocations
    // Use bytes iterator for better performance (ASCII only)
    let mut nybbles = Vec::with_capacity(hex_str.len());
    for &byte in hex_str.as_bytes() {
        let nybble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => 0,
        };
        nybbles.push(nybble);
    }
    nybbles
}

fn create_hardware_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("Failed to get hardware entropy");
    ChaCha20Rng::from_seed(seed)
}

#[inline]
fn hex_encode(data: &[u8]) -> String {
    // Use exact capacity for common sizes to avoid reallocations
    let capacity = match data.len() {
        16 => 32,  // IV
        20 => 40,  // Address
        32 => 64,  // Private key, salt, derived key, MAC
        64 => 128, // SHA3-256 hash
        _ => data.len() * 2, // Fallback for other sizes
    };
    // Use unsafe construction for better performance - hex digits are always valid ASCII
    let mut hex_bytes = Vec::with_capacity(capacity);
    for &byte in data {
        hex_bytes.push(b"0123456789abcdef"[(byte >> 4) as usize]);
        hex_bytes.push(b"0123456789abcdef"[(byte & 0x0F) as usize]);
    }
    unsafe { String::from_utf8_unchecked(hex_bytes) }
}

fn generate_random_password(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789";
    let mut rng = create_hardware_rng();

    // Use unsafe String construction for better performance
    // CHARSET only contains ASCII, so this is safe
    let mut password = Vec::with_capacity(len);
    password.resize(len, 0);
    for byte in &mut password {
        let idx = (rng.next_u32() as usize) % CHARSET.len();
        *byte = CHARSET[idx];
    }

    unsafe { String::from_utf8_unchecked(password) }
}

#[inline(always)]
fn match_prefix_suffix_bytes(addr: &[u8], start_hex: &[u8], end_hex: &[u8]) -> bool {
    #[inline(always)]
    fn nybble(addr: &[u8], i: usize) -> u8 {
        if i % 2 == 0 { 
            addr[i / 2] >> 4 
        } else { 
            addr[i / 2] & 0x0F 
        }
    }

    // Check prefix - early return for better branch prediction
    for (i, &expected) in start_hex.iter().enumerate() {
        if nybble(addr, i) != expected {
            return false;
        }
    }

    // Check suffix
    let suffix_len = end_hex.len();
    if suffix_len > 0 {
        let total_nybbles = 40;
        let suffix_start = total_nybbles - suffix_len;

        for (i, &expected) in end_hex.iter().enumerate() {
            if nybble(addr, suffix_start + i) != expected {
                return false;
            }
        }
    }

    true
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    if args.count == 0 {
        return Err("Number of wallets must be greater than 0".into());
    }
    if args.start_pattern.len() > 40 || args.end_pattern.len() > 40 {
        return Err("Pattern length cannot exceed 40 characters".into());
    }
    
    // Convert to lowercase once and reuse
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

    // Prepare the Generator Point G (Public Key of 1) and Scalar 1
    let one_bytes = [
        0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 1
    ];
    let scalar_one = Scalar::from_be_bytes(one_bytes).unwrap();
    // We need a Secp context
    static SECP: LazyLock<Secp256k1<secp256k1::All>> = LazyLock::new(Secp256k1::new);
    let g_point = PublicKey::from_secret_key(&SECP, &SecretKey::from_byte_array(one_bytes).unwrap());

    // Create threads manually instead of using rayon
    let mut handles = Vec::with_capacity(thread_count);
    for seed in seeds {
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
        let pattern_difficulty = pattern_difficulty;
        
        let handle = thread::spawn(move || {
            let mut rng = ChaCha20Rng::from_seed(seed);

            // Initialize starting point for Step Optimization
            let mut private_key_bytes = [0u8; 32];
            rng.fill_bytes(&mut private_key_bytes);
            let mut current_sk = SecretKey::from_byte_array(private_key_bytes).unwrap_or_else(|_| {
                 // Fallback if random bytes are invalid (extremely rare)
                 SecretKey::from_byte_array([1u8; 32]).unwrap()
            });
            let initial_sk = current_sk;
            let mut current_pk = PublicKey::from_secret_key(&SECP, &current_sk);
            
            // Reuse Keccak hasher to avoid allocation
            let mut hasher = Keccak256::new();
            
            // Local counters to reduce atomic contention
            let mut local_steps: u64 = 0;
            const BATCH_SIZE: u64 = 2048;

            loop {
                // Batch reporting and check
                if local_steps % BATCH_SIZE == 0 && local_steps > 0 {
                    total_attempts.fetch_add(BATCH_SIZE, Ordering::Relaxed);
                    
                    // Check if we are done
                    if found_count.load(Ordering::Acquire) >= args_count {
                        break;
                    }

                    // Progress printing (approximate)
                    let current_global = total_attempts.load(Ordering::Relaxed);
                    if current_global % progress_interval < BATCH_SIZE {
                        let elapsed = start_time.elapsed();
                        let rate = current_global as f64 / elapsed.as_secs_f64();
                        let found = found_count.load(Ordering::Relaxed);
                        
                        // ETA logic...
                        let remaining_wallets = args_count.saturating_sub(found);
                        let eta_seconds = if rate > 0.0 && remaining_wallets > 0 && found > 0 {
                            let attempts_per_wallet = current_global as f64 / found as f64;
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
                            current_global / 1_000_000,
                            found,
                            args_count,
                            rate / 1_000.0,
                            eta_str
                        );
                    }
                }

                // Return Option<(Wallet, Option<Mnemonic>)> 
                let step_result = if args_show_mnemonic {
                    // Mnemonic path - slow path
                    let mut entropy = [0u8; 16];
                    rng.fill_bytes(&mut entropy);

                    match Mnemonic::from_entropy(&entropy) {
                        Ok(mnemonic) => {
                            match SimpleWallet::from_mnemonic(&mnemonic) {
                                Ok(wallet) => Some((wallet, Some(mnemonic))),
                                Err(_) => None,
                            }
                        },
                        Err(_) => None,
                    }
                } else {
                    // Fast path - Step Optimization
                    
                    // 1. Serialize Public Key (Compressed or Uncompressed)
                    let pub_bytes = current_pk.serialize_uncompressed();

                    // 2. Keccak256 Hash to get address - reusing hasher
                    hasher.update(&pub_bytes[1..]);
                    let hash = hasher.finalize_reset();
                    
                    // 3. Check Match - pass slice directly
                    let addr_bytes = &hash[12..];
                    
                    if match_prefix_suffix_bytes(addr_bytes, &start_nybbles, &end_nybbles) {
                         // Reconstruct private key only when match found
                         let mut steps_bytes = [0u8; 32];
                         steps_bytes[24..].copy_from_slice(&local_steps.to_be_bytes());
                         let scalar_steps = Scalar::from_be_bytes(steps_bytes).unwrap();
                         let matched_sk = initial_sk.add_tweak(&scalar_steps).unwrap();
                         let wallet = SimpleWallet::new(matched_sk);
                         Some((wallet, None))
                    } else {
                        // 4. STEP: Add G to Public Key
                        current_pk = current_pk.combine(&g_point).expect("Point addition failed");
                        None 
                    }
                };

                // Increment steps/attempts
                local_steps += 1;

                // Handle the result
                let (wallet, mnemonic) = match step_result {
                    Some((w, m)) => (w, m),
                    None => continue,
                };

                let addr_bytes = wallet.address();
        
                // Check match again for mnemonic path (fast path already checked)
                let is_match = if args_show_mnemonic {
                     match_prefix_suffix_bytes(&addr_bytes, &start_nybbles, &end_nybbles)
                } else {
                     true
                };

                if is_match {
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
                        // Another thread finished the job
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
