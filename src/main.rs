use bip39::Mnemonic;
use k256::{SecretKey, Scalar, ProjectivePoint};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::BatchNormalize;
use k256::U256; 
use k256::elliptic_curve::bigint::Encoding; // Correct path

use rand::rngs::StdRng; // Use StdRng (usually ChaCha12)
use rand::{RngCore, SeedableRng};
use bip32::XPrv;
use scrypt::{scrypt, Params as ScryptParams};
use aes::Aes128;
use ctr::Ctr32BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
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

// Simple wallet struct using k256
struct SimpleWallet {
    private_key: SecretKey,
    address: [u8; 20],
}

impl SimpleWallet {
    #[inline]
    fn new(private_key: SecretKey) -> Self {
        let public_key = private_key.public_key();
        let pub_point = public_key.to_encoded_point(false);
        let pub_bytes = pub_point.as_bytes();

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
        
        // bip32 XPrv returns bytes that need conversion to k256::SecretKey
        let private_key = SecretKey::from_slice(&xprv.to_bytes())?;
        Ok(Self::new(private_key))
    }
    
    #[inline]
    fn address(&self) -> [u8; 20] {
        self.address
    }
    
    #[inline]
    fn to_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes().into()
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

    #[arg(short = 'o', long = "output-dir")]
    output_dir: Option<String>,

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

fn create_hardware_rng() -> StdRng {
    let mut seed = [0u8; 32];
    // Use rand::rng() which is cryptographically secure and seeded from OS
    rand::rng().fill_bytes(&mut seed);
    StdRng::from_seed(seed)
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
fn match_prefix_suffix_bytes(
    addr: &[u8], 
    start_hex: &[u8], 
    end_hex: &[u8],
    fast_fail: Option<u8>
) -> bool {
    // Fast fail optimization: Check first byte directly
    // This avoids loop setup and bitwise ops for 99.6% of non-matches
    if let Some(expected) = fast_fail {
        if addr[0] != expected {
            return false;
        }
    }

    #[inline(always)]
    fn nybble(addr: &[u8], i: usize) -> u8 {
        if i % 2 == 0 { 
            addr[i / 2] >> 4 
        } else { 
            addr[i / 2] & 0x0F 
        }
    }

    // Check prefix
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

fn format_metric(n: f64) -> String {
    if n >= 1e9 {
        format!("{:.2}G", n / 1e9)
    } else if n >= 1e6 {
        format!("{:.2}M", n / 1e6)
    } else if n >= 1e3 {
        format!("{:.2}k", n / 1e3)
    } else {
        format!("{:.0}", n)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Set default output directory to ~/.cache/genwallet if not specified
    let output_dir = args.output_dir.unwrap_or_else(|| {
        std::env::var("HOME")
            .map(|home| format!("{}/.cache/genwallet", home))
            .unwrap_or_else(|_| "/tmp/genwallet".to_string())
    });
    
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
    
    // Pre-calculate fast fail byte (first 2 nybbles)
    let fast_fail_byte = if start_nybbles.len() >= 2 {
        Some((start_nybbles[0] << 4) | start_nybbles[1])
    } else {
        None
    };

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

    // Create seeds once using hardware entropy
    let mut master_rng = create_hardware_rng();
    let seeds: Vec<[u8; 32]> = (0..thread_count)
        .map(|_| {
            let mut seed = [0u8; 32];
            master_rng.fill_bytes(&mut seed);
            seed
        })
        .collect();

    // Monitor thread for progress reporting
    let monitor_found = found_count.clone();
    let monitor_attempts = total_attempts.clone();
    let monitor_start = Instant::now();
    let monitor_args_count = args.count;
    let monitor_difficulty = pattern_difficulty;
    
    thread::spawn(move || {
        let mut last_attempts = 0;
        let mut last_time = Instant::now();
        
        loop {
            thread::sleep(std::time::Duration::from_secs(1));
            
            let current_found = monitor_found.load(Ordering::Relaxed);
            if current_found >= monitor_args_count {
                break;
            }
            
            let current_attempts = monitor_attempts.load(Ordering::Relaxed);
            let total_elapsed = monitor_start.elapsed();
            let step_elapsed = last_time.elapsed();
            
            let delta_attempts = current_attempts.saturating_sub(last_attempts);
            let instant_rate = delta_attempts as f64 / step_elapsed.as_secs_f64();
            let avg_rate = current_attempts as f64 / total_elapsed.as_secs_f64();
            
            // ETA logic based on INSTANT rate
            let remaining_wallets = monitor_args_count.saturating_sub(current_found);
            let eta_seconds = if instant_rate > 0.0 && remaining_wallets > 0 {
                let attempts_per_wallet = if current_found > 0 {
                    current_attempts as f64 / current_found as f64
                } else {
                    monitor_difficulty
                };
                (attempts_per_wallet * remaining_wallets as f64) / instant_rate
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
                "\r[Progress] Attempts: {} | Found: {}/{} | Speed: {}/s (Avg: {}/s) | ETA: {}   ",
                format_metric(current_attempts as f64),
                current_found,
                monitor_args_count,
                format_metric(instant_rate),
                format_metric(avg_rate),
                eta_str
            );
            
            last_attempts = current_attempts;
            last_time = Instant::now();
        }
    });

    // Create threads manually instead of using rayon
    let g_point = ProjectivePoint::GENERATOR;
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
        let output_dir = output_dir.clone();
        let args_show_full_key = args.show_full_key;
        
        let handle = thread::spawn(move || {
            let mut rng = StdRng::from_seed(seed);

            // Initialize starting point
            let mut private_key_bytes = [0u8; 32];
            rng.fill_bytes(&mut private_key_bytes);
            
            // Ensure valid scalar
            let current_sk = SecretKey::from_slice(&private_key_bytes).unwrap_or_else(|_| {
                 SecretKey::from_slice(&[1u8; 32]).unwrap()
            });
            let initial_sk = current_sk.clone();
            
            // Convert to ProjectivePoint for fast addition
            let mut current_point = ProjectivePoint::from(current_sk.public_key());
            
            // Reuse Keccak hasher
            let mut hasher = Keccak256::new();
            
            // Local counters
            let mut local_steps: u64 = 0;
            const BATCH_SIZE: usize = 2048; // Stable peak amortization without cache thrashing
            const REPORT_BATCH_SIZE: u64 = 262_144; // Reduced contention (~250k steps)

            // Pre-calculate increments: 1G, 2G, ... 32G as AffinePoints for mixed addition
            // Adding Affine to Projective is faster than Projective + Projective
            let mut increments = Vec::with_capacity(BATCH_SIZE);
            let mut curr_g = g_point;
            for _ in 0..BATCH_SIZE {
                increments.push(curr_g.to_affine()); // Store as Affine
                curr_g += g_point;
            }
            // curr_g is now (BATCH_SIZE + 1)G, but we want step_batch_g = BATCH_SIZE * G
            // The last element in increments is exactly BATCH_SIZE * G
            let step_batch_g = ProjectivePoint::from(*increments.last().unwrap());

            loop {
                // Batch reporting and check
                if local_steps % REPORT_BATCH_SIZE == 0 && local_steps > 0 {
                    total_attempts.fetch_add(REPORT_BATCH_SIZE, Ordering::Relaxed);
                    
                    if found_count.load(Ordering::Acquire) >= args_count {
                        break;
                    }
                }

                if args_show_mnemonic {
                    // Mnemonic path (slow, no batching needed)
                    let mut entropy = [0u8; 16];
                    rng.fill_bytes(&mut entropy);
                    if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) {
                        if let Ok(wallet) = SimpleWallet::from_mnemonic(&mnemonic) {
                            let addr_bytes = wallet.address();
                            if match_prefix_suffix_bytes(&addr_bytes, &start_nybbles, &end_nybbles, fast_fail_byte) {
                                // Found via mnemonic!
                                // ... handle success ...
                                let addr_hex = hex_encode(&addr_bytes);
                                let private_key_bytes = wallet.to_bytes();

                                let idx = found_count.fetch_add(1, Ordering::AcqRel);
                                if idx < args_count {
                                    match save_encrypted_wallet(&wallet, &password, &output_dir) {
                                        Ok(path) => {
                                            println!("\n🎉 Found wallet {} of {}", idx + 1, args_count);
                                            println!("Address:    0x{}", addr_hex);
                                            println!("PrivateKey: {}", hex_encode(&private_key_bytes));
                                            println!("Mnemonic:   {}", mnemonic.to_string());
                                            println!("Saved to:   {}", path);
                                            println!("---");
                                            sender.send((addr_hex, hex_encode(&private_key_bytes), path)).ok();
                                        }
                                        Err(e) => eprintln!("Error: {}", e),
                            }
                                } else { break; }
                            }
                        }
                    }
                    local_steps += 1;
                    continue;
                }

                // Fast Path: Batch Optimization
                
                // 1. Generate batch of 8 points: P, P+G, ..., P+7G
                // We actually want P+0, P+1, ... P+7
                // But current_point is P.
                // We add our pre-calc increments.
                let mut batch_points = [ProjectivePoint::IDENTITY; BATCH_SIZE];
                // Manually unroll or loop? Loop is fine, compiler unrolls.
                for i in 0..BATCH_SIZE {
                    // This is (Base + i*G) - we precalculated i*G (1-based), 
                    // so we need 0-based.
                    // P_0 = current_point
                    // P_i = current_point + increments[i-1] (where increments are Affine)
                    if i == 0 {
                        batch_points[0] = current_point;
                } else {
                        batch_points[i] = current_point + increments[i-1];
                    }
                }

                // 2. Batch Normalize (THE KEY SPEEDUP)
                // Converts all 8 Projective points to Affine points with 1 inversion
                let affine_points = ProjectivePoint::batch_normalize(&batch_points);

                // 3. Process batch
                for (i, point) in affine_points.iter().enumerate() {
                    // Access coordinates via ToEncodedPoint (robust)
                    let encoded = point.to_encoded_point(false);
                    let x = encoded.x().unwrap();
                    let y = encoded.y().unwrap();

                    // Keccak-256 hash of (X || Y)
                    hasher.update(x);
                    hasher.update(y);
                    let hash = hasher.finalize_reset();
                    let addr_bytes = &hash[12..];
                    
                    if match_prefix_suffix_bytes(addr_bytes, &start_nybbles, &end_nybbles, fast_fail_byte) {
                        // Found match! Reconstruct Private Key
                        let offset = local_steps + i as u64;
                         let mut steps_bytes = [0u8; 32];
                        steps_bytes[24..].copy_from_slice(&offset.to_be_bytes());
                        
                        // Convert offset to Scalar
                        let offset_uint = U256::from_be_bytes(steps_bytes);
                        // Use reduce to ensure it fits in field
                        let scalar = <Scalar as Reduce<U256>>::reduce(offset_uint);
                        
                        // Add scalar to secret key: sk_new = sk + offset
                        let sk_scalar = initial_sk.to_nonzero_scalar();
                        let matched_scalar = sk_scalar.as_ref() + scalar;
                        let matched_sk = SecretKey::new(matched_scalar.into());
                        
                        let wallet = SimpleWallet::new(matched_sk);
                        
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
                                        println!("PrivateKey: {}", redact_private_key(&hex_encode(&private_key_bytes)));
                                }
                                println!("Saved to:   {}", path);
                                println!("---");
                                    sender.send((addr_hex, hex_encode(&private_key_bytes), path)).ok();
                            }
                                Err(e) => eprintln!("Error: {}", e),
                        }
                    } else {
                            // Another thread finished
                            return; // Break outer loop
                        }
                    }
                }

                // Advance base point by batch size for next batch
                current_point += step_batch_g;
                local_steps += BATCH_SIZE as u64;
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
        println!("All wallets saved to: {}", output_dir);
    }
    println!("\nTotal time: {:.2?}", elapsed);

    Ok(())
}
