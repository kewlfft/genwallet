use bip39::Mnemonic;
use ethers::signers::{Signer, Wallet, MnemonicBuilder, coins_bip39::English};
use ethers::core::k256::ecdsa::SigningKey;
use eth_keystore::encrypt_key;
use rand_chacha::ChaCha20Rng;
use rand::{RngCore, SeedableRng, thread_rng};
use getrandom::getrandom;
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use clap::Parser;
use std::fs;
use std::path::Path;
use rpassword::prompt_password;
use crossbeam::channel::unbounded;
use hex;
use num_cpus;


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
    wallet: &Wallet<SigningKey>,
    password: &str,
    output_dir: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let addr = format!("{:x}", wallet.address());
    let file_path = Path::new(output_dir).join(format!("{}.json", addr));

    let private_key_bytes = wallet.signer().to_bytes();

    encrypt_key(
        output_dir,
        &mut thread_rng(),
        &private_key_bytes.as_slice(),
        password,
        Some(&format!("{}.json", addr)),
    )?;

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
    getrandom(&mut seed).expect("Failed to get hardware entropy");
    ChaCha20Rng::from_seed(seed)
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

    unsafe { String::from_utf8_unchecked(password) }
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

    let thread_count = args.threads.unwrap_or_else(num_cpus::get);

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
    let (sender, receiver) = unbounded();
    let start_time = Instant::now();
    let progress_interval = if args.show_mnemonic { 10_000 } else { 100_000 };

    if args.show_mnemonic {
        // Mnemonic path - uses hardware RNG
        (0..thread_count).into_par_iter().enumerate().for_each_with(
            (sender, total_attempts.clone()),
            |(s, attempts), (_thread_id, _)| {
                let mut rng = create_hardware_rng();

                while found_count.load(Ordering::Acquire) < args.count {
                    let mut entropy = [0u8; 16];
                    rng.fill_bytes(&mut entropy);

                    let mnemonic = match Mnemonic::from_entropy(&entropy) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };

                    let wallet = match MnemonicBuilder::<English>::default()
                        .phrase(mnemonic.to_string().as_str())
                        .build() 
                    {
                        Ok(w) => w,
                        Err(_) => continue,
                    };

                    let address = wallet.address();
                    let addr_bytes = address.0;

                    // Update attempt count
                    let current_attempts = attempts.fetch_add(1, Ordering::Relaxed);
                    if current_attempts % progress_interval == 0 {
                        let elapsed = start_time.elapsed();
                        let rate = current_attempts as f64 / elapsed.as_secs_f64();
                        let found = found_count.load(Ordering::Relaxed);

                        let remaining_wallets = args.count.saturating_sub(found);
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
                            args.count,
                            rate / 1_000.0,
                            eta_str
                        );
                    }

                    if match_prefix_suffix_bytes(&addr_bytes, &start_nybbles, &end_nybbles) {
                        let addr_hex = hex::encode(addr_bytes);
                        let private_key_bytes = wallet.signer().to_bytes();

                        let idx = found_count.fetch_add(1, Ordering::AcqRel);
                        if idx < args.count {
                            match save_encrypted_wallet(&wallet, &password, &args.output_dir) {
                                Ok(path) => {
                                    println!("\n🎉 Found wallet {} of {}", idx + 1, args.count);
                                    println!("Address:    0x{}", addr_hex);
                                    if args.show_full_key {
                                        println!("PrivateKey: {}", hex::encode(private_key_bytes.as_slice()));
                                    } else {
                                        println!(
                                            "PrivateKey: {}",
                                            redact_private_key(&hex::encode(private_key_bytes.as_slice()))
                                        );
                                    }
                                    println!("Mnemonic:   {}", mnemonic.to_string());
                                    println!("Saved to:   {}", path);
                                    println!("---");

                                    s.send((addr_hex, hex::encode(private_key_bytes.as_slice()), path))
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
            },
        );
    } else {
        // Fast path - uses thread_rng for better performance
        (0..thread_count).into_par_iter().enumerate().for_each_with(
            (sender, total_attempts.clone()),
            |(s, attempts), (_thread_id, _)| {
                let mut rng = thread_rng();

                while found_count.load(Ordering::Acquire) < args.count {
                    let wallet = Wallet::new(&mut rng);
                    let address = wallet.address();
                    let addr_bytes = address.0;

                    // Update attempt count
                    let current_attempts = attempts.fetch_add(1, Ordering::Relaxed);
                    if current_attempts % progress_interval == 0 {
                        let elapsed = start_time.elapsed();
                        let rate = current_attempts as f64 / elapsed.as_secs_f64();
                        let found = found_count.load(Ordering::Relaxed);

                        let remaining_wallets = args.count.saturating_sub(found);
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
                            args.count,
                            rate / 1_000.0,
                            eta_str
                        );
                    }

                    if match_prefix_suffix_bytes(&addr_bytes, &start_nybbles, &end_nybbles) {
                        let addr_hex = hex::encode(addr_bytes);
                        let private_key_bytes = wallet.signer().to_bytes();

                        let idx = found_count.fetch_add(1, Ordering::AcqRel);
                        if idx < args.count {
                            match save_encrypted_wallet(&wallet, &password, &args.output_dir) {
                                Ok(path) => {
                                    println!("\n🎉 Found wallet {} of {}", idx + 1, args.count);
                                    println!("Address:    0x{}", addr_hex);
                                    if args.show_full_key {
                                        println!("PrivateKey: {}", hex::encode(private_key_bytes.as_slice()));
                                    } else {
                                        println!(
                                            "PrivateKey: {}",
                                            redact_private_key(&hex::encode(private_key_bytes.as_slice()))
                                        );
                                    }
                                    println!("Saved to:   {}", path);
                                    println!("---");

                                    s.send((addr_hex, hex::encode(private_key_bytes.as_slice()), path))
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
            },
        );
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
