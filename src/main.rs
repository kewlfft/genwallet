#[cfg(feature = "mnemonic")]
use bip39::Mnemonic;
use k256::{AffinePoint, NonZeroScalar, ProjectivePoint, Scalar, SecretKey};
use k256::elliptic_curve::point::{AffineCoordinates, BatchNormalize};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
#[cfg(feature = "mnemonic")]
use bip32::XPrv;
use scrypt::{scrypt, Params as ScryptParams};
use aes::Aes128;
use ctr::Ctr32BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use clap::Parser;
use std::fs;
use std::path::Path;
use rpassword::prompt_password;
use std::sync::mpsc;
use std::thread;
use sha3::{Keccak256, Digest};
use indicatif::{ProgressBar, ProgressStyle};

struct SimpleWallet {
    private_key: SecretKey,
    address: [u8; 20],
}

impl SimpleWallet {
    fn new(private_key: SecretKey) -> Self {
        let public_key = private_key.public_key();
        let point = public_key.as_affine();
        let mut hasher = Keccak256::new();
        hasher.update(point.x());
        hasher.update(point.y());
        let hash = hasher.finalize();

        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        Self { private_key, address }
    }

    #[cfg(feature = "mnemonic")]
    fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Self, Box<dyn std::error::Error>> {
        let seed = mnemonic.to_seed("");
        let mut xprv = XPrv::new(&seed)?;
        // m/44'/60'/0'/0/0
        xprv = xprv.derive_child(bip32::ChildNumber::new(44, true)?)?;
        xprv = xprv.derive_child(bip32::ChildNumber::new(60, true)?)?;
        xprv = xprv.derive_child(bip32::ChildNumber::new(0, true)?)?;
        xprv = xprv.derive_child(bip32::ChildNumber::new(0, false)?)?;
        xprv = xprv.derive_child(bip32::ChildNumber::new(0, false)?)?;
        Ok(Self::new(SecretKey::from_slice(&xprv.to_bytes())?))
    }

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

    #[arg(short = 't', long = "threads")]
    threads: Option<usize>,

    /// Search via BIP39 mnemonics (requires `--features mnemonic`)
    #[cfg(feature = "mnemonic")]
    #[arg(long = "show-mnemonic")]
    show_mnemonic: bool,
}

fn redact_private_key(private_key: &str) -> String {
    format!("{}...{}", &private_key[..4], &private_key[private_key.len() - 4..])
}

fn save_encrypted_wallet(
    wallet: &SimpleWallet,
    password: &str,
    output_dir: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let addr = hex::encode(wallet.address);
    let file_path = Path::new(output_dir).join(format!("{}.json", addr));
    let private_key_bytes = wallet.to_bytes();

    let mut rng = rand::rng();
    let mut salt = [0u8; 32];
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    // ethers.js-compatible scrypt: n=2^18=262144, r=8, p=1
    let mut derived_key = [0u8; 32];
    let scrypt_params = ScryptParams::new(18, 8, 1).unwrap();
    scrypt(password.as_bytes(), &salt, &scrypt_params, &mut derived_key).unwrap();

    let mut cipher = Ctr32BE::<Aes128>::new_from_slices(&derived_key[..16], &iv).unwrap();
    let mut ciphertext = private_key_bytes;
    cipher.apply_keystream(&mut ciphertext);

    let mut mac_hasher = Keccak256::new();
    mac_hasher.update(&derived_key[16..32]);
    mac_hasher.update(&ciphertext);
    let mac = mac_hasher.finalize();

    let id = format!(
        "{:x}-{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        rng.next_u64()
    );

    let keystore = serde_json::json!({
        "version": 3,
        "id": id,
        "address": format!("0x{addr}"),
        "crypto": {
            "ciphertext": hex::encode(ciphertext),
            "cipherparams": { "iv": hex::encode(iv) },
            "cipher": "aes-128-ctr",
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "salt": hex::encode(salt),
                "n": 262144,
                "r": 8,
                "p": 1,
            },
            "mac": hex::encode(mac),
        },
    });

    fs::write(&file_path, serde_json::to_string_pretty(&keystore)?)?;
    Ok(file_path.display().to_string())
}

fn report_found(
    pb: &ProgressBar,
    idx: usize,
    count: usize,
    addr_hex: &str,
    private_key_bytes: &[u8; 32],
    path: &str,
    show_full_key: bool,
    #[cfg(feature = "mnemonic")] mnemonic: Option<&str>,
) {
    // suspend so messages print even when the bar draw target is hidden (non-TTY)
    pb.suspend(|| {
        println!("\n🎉 Found wallet {} of {}", idx + 1, count);
        println!("Address:    0x{}", addr_hex);
        let pk = hex::encode(private_key_bytes);
        if show_full_key {
            println!("PrivateKey: {}", pk);
        } else {
            println!("PrivateKey: {}", redact_private_key(&pk));
        }
        #[cfg(feature = "mnemonic")]
        if let Some(m) = mnemonic {
            println!("Mnemonic:   {}", m);
        }
        println!("Saved to:   {}", path);
        println!("---");
    });
}

fn hex_to_nybbles(hex_str: &str) -> Vec<u8> {
    hex_str
        .bytes()
        .map(|byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => 0,
        })
        .collect()
}

fn generate_random_password(len: usize) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    let password: Vec<u8> = (0..len)
        .map(|_| CHARSET[(rng.next_u32() as usize) % CHARSET.len()])
        .collect();
    // SAFETY: CHARSET is ASCII
    unsafe { String::from_utf8_unchecked(password) }
}

#[inline(always)]
fn match_prefix_suffix_bytes(
    addr: &[u8],
    start_hex: &[u8],
    end_hex: &[u8],
    fast_fail: Option<u8>,
) -> bool {
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

    for (i, &expected) in start_hex.iter().enumerate() {
        if nybble(addr, i) != expected {
            return false;
        }
    }

    if !end_hex.is_empty() {
        let suffix_start = 40 - end_hex.len();
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

fn format_eta(secs: f64) -> String {
    if !secs.is_finite() || secs <= 0.0 {
        "∞".into()
    } else if secs < 60.0 {
        format!("{:.0}s", secs)
    } else if secs < 3600.0 {
        format!("{:.0}m", secs / 60.0)
    } else if secs < 86400.0 {
        format!("{:.1}h", secs / 3600.0)
    } else {
        format!("{:.1}d", secs / 86400.0)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let output_dir = args.output_dir.unwrap_or_else(|| {
        dirs::cache_dir()
            .map(|p| p.join("genwallet").to_string_lossy().into_owned())
            .unwrap_or_else(|| "/tmp/genwallet".to_string())
    });

    if args.count == 0 {
        return Err("Number of wallets must be greater than 0".into());
    }
    if args.start_pattern.len() > 40 || args.end_pattern.len() > 40 {
        return Err("Pattern length cannot exceed 40 characters".into());
    }

    let pattern_start = args.start_pattern.to_lowercase();
    let pattern_end = args.end_pattern.to_lowercase();
    let start_nybbles = Arc::<[u8]>::from(hex_to_nybbles(&pattern_start));
    let end_nybbles = Arc::<[u8]>::from(hex_to_nybbles(&pattern_end));

    let fast_fail_byte = if start_nybbles.len() >= 2 {
        Some((start_nybbles[0] << 4) | start_nybbles[1])
    } else {
        None
    };

    let pattern_difficulty =
        16.0_f64.powi((pattern_start.len() + pattern_end.len()) as i32);

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

    let estimate = (pattern_difficulty * args.count as f64).ceil().max(1.0) as u64;
    let pb = ProgressBar::new(estimate);
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] Attempts: {pos} | Found: {msg} | {per_sec} | ETA: {eta}",
        )?
        .with_key("pos", |state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
            write!(w, "{}", format_metric(state.pos() as f64)).unwrap()
        })
        .with_key("per_sec", |state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
            write!(w, "{}/s", format_metric(state.per_sec())).unwrap()
        })
        .with_key("eta", |state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
            write!(w, "{}", format_eta(state.eta().as_secs_f64())).unwrap()
        })
        .progress_chars("##-"),
    );
    pb.set_message(format!("0/{}", args.count));

    let monitor_found = found_count.clone();
    let monitor_attempts = total_attempts.clone();
    let monitor_args_count = args.count;
    let monitor_difficulty = pattern_difficulty;
    let monitor_pb = pb.clone();

    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(1));

            let current_found = monitor_found.load(Ordering::Relaxed);
            if current_found >= monitor_args_count {
                break;
            }

            let current_attempts = monitor_attempts.load(Ordering::Relaxed);
            let attempts_per_wallet = if current_found > 0 {
                current_attempts as f64 / current_found as f64
            } else {
                monitor_difficulty
            };
            let remaining = monitor_args_count.saturating_sub(current_found);
            let target = current_attempts
                .saturating_add((attempts_per_wallet * remaining as f64) as u64)
                .max(current_attempts.saturating_add(1));

            monitor_pb.set_length(target);
            monitor_pb.set_position(current_attempts);
            monitor_pb.set_message(format!("{}/{}", current_found, monitor_args_count));
        }
    });

    let mut master_rng = rand::rng();
    let mut handles = Vec::with_capacity(thread_count);
    for _ in 0..thread_count {
        let mut seed = [0u8; 32];
        master_rng.fill_bytes(&mut seed);

        let sender = sender.clone();
        let total_attempts = total_attempts.clone();
        let found_count = found_count.clone();
        let start_nybbles = start_nybbles.clone();
        let end_nybbles = end_nybbles.clone();
        let args_count = args.count;
        #[cfg(feature = "mnemonic")]
        let args_show_mnemonic = args.show_mnemonic;
        let password = password.clone();
        let output_dir = output_dir.clone();
        let args_show_full_key = args.show_full_key;
        let pb = pb.clone();

        handles.push(thread::spawn(move || {
            let mut rng = StdRng::from_seed(seed);

            let mut private_key_bytes = [0u8; 32];
            rng.fill_bytes(&mut private_key_bytes);

            let initial_sk = SecretKey::from_slice(&private_key_bytes).unwrap_or_else(|_| {
                SecretKey::from_slice(&[1u8; 32]).unwrap()
            });
            let mut current_point = ProjectivePoint::from(initial_sk.public_key());
            let mut hasher = Keccak256::new();

            let mut local_steps: u64 = 0;
            const BATCH_SIZE: usize = 2048;
            const REPORT_BATCH_SIZE: u64 = 262_144;

            let g_affine = AffinePoint::GENERATOR;
            let mut batch_points = [ProjectivePoint::IDENTITY; BATCH_SIZE];

            loop {
                if local_steps % REPORT_BATCH_SIZE == 0 && local_steps > 0 {
                    total_attempts.fetch_add(REPORT_BATCH_SIZE, Ordering::Relaxed);
                    if found_count.load(Ordering::Acquire) >= args_count {
                        break;
                    }
                }

                #[cfg(feature = "mnemonic")]
                if args_show_mnemonic {
                    let mut entropy = [0u8; 16];
                    rng.fill_bytes(&mut entropy);
                    if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) {
                        if let Ok(wallet) = SimpleWallet::from_mnemonic(&mnemonic) {
                            let addr_bytes = wallet.address;
                            if match_prefix_suffix_bytes(
                                &addr_bytes,
                                &start_nybbles,
                                &end_nybbles,
                                fast_fail_byte,
                            ) {
                                let addr_hex = hex::encode(addr_bytes);
                                let private_key_bytes = wallet.to_bytes();
                                let idx = found_count.fetch_add(1, Ordering::AcqRel);
                                if idx < args_count {
                                    match save_encrypted_wallet(&wallet, &password, &output_dir) {
                                        Ok(path) => {
                                            report_found(
                                                &pb,
                                                idx,
                                                args_count,
                                                &addr_hex,
                                                &private_key_bytes,
                                                &path,
                                                true,
                                                Some(&mnemonic.to_string()),
                                            );
                                            sender.send(()).ok();
                                        }
                                        Err(e) => {
                                            pb.suspend(|| eprintln!("Error: {}", e));
                                        }
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    local_steps += 1;
                    continue;
                }

                let mut p = current_point;
                for slot in &mut batch_points {
                    *slot = p;
                    p += g_affine;
                }

                let affine_points =
                    <ProjectivePoint as BatchNormalize<_>>::batch_normalize_vartime(&batch_points);

                for (i, point) in affine_points.iter().enumerate() {
                    hasher.update(point.x());
                    hasher.update(point.y());
                    let hash = hasher.finalize_reset();
                    let addr_bytes = &hash[12..];

                    if match_prefix_suffix_bytes(
                        addr_bytes,
                        &start_nybbles,
                        &end_nybbles,
                        fast_fail_byte,
                    ) {
                        let offset = local_steps + i as u64;
                        let matched_scalar =
                            initial_sk.to_nonzero_scalar().as_ref() + Scalar::from(offset);
                        let matched_sk = SecretKey::from(
                            NonZeroScalar::new(matched_scalar).expect("matched scalar nonzero"),
                        );
                        let wallet = SimpleWallet::new(matched_sk);

                        let addr_hex = hex::encode(addr_bytes);
                        let private_key_bytes = wallet.to_bytes();
                        let idx = found_count.fetch_add(1, Ordering::AcqRel);
                        if idx < args_count {
                            match save_encrypted_wallet(&wallet, &password, &output_dir) {
                                Ok(path) => {
                                    report_found(
                                        &pb,
                                        idx,
                                        args_count,
                                        &addr_hex,
                                        &private_key_bytes,
                                        &path,
                                        args_show_full_key,
                                        #[cfg(feature = "mnemonic")]
                                        None,
                                    );
                                    sender.send(()).ok();
                                }
                                Err(e) => {
                                    pb.suspend(|| eprintln!("Error: {}", e));
                                }
                            }
                        } else {
                            return;
                        }
                    }
                }

                current_point = p;
                local_steps += BATCH_SIZE as u64;
            }
        }));
    }

    drop(sender);
    for handle in handles {
        handle.join().unwrap();
    }

    let mut found = 0usize;
    while receiver.recv().is_ok() {
        found += 1;
    }

    pb.finish_and_clear();

    let elapsed = start_time.elapsed();
    let total_attempts = total_attempts.load(Ordering::Relaxed);
    let rate = total_attempts as f64 / elapsed.as_secs_f64();

    println!("\n=== Summary ===");
    println!("Generated {} wallet(s) successfully", found);
    println!("Total attempts: {}M", total_attempts / 1_000_000);
    println!("Average rate: {:.0}K attempts/second", rate / 1_000.0);
    if args.count > 1 {
        println!("All wallets saved to: {}", output_dir);
    }
    println!("\nTotal time: {:.2?}", elapsed);

    Ok(())
}
