//! Hot-path microbenchmark: previous (k256 0.13-style) vs new (k256 0.14-style).
//!
//! Measures addresses/sec for the vanity-search inner loop:
//!   mixed EC adds → batch normalize → keccak(x‖y) → address bytes
//!
//! Run:
//!   cargo bench --bench hotpath_compare
//!
//! Or (same binary, quieter):
//!   cargo run --release --bench hotpath_compare

use std::hint::black_box;
use std::time::{Duration, Instant};

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use sha3::{Digest, Keccak256};

const BATCH_SIZE: usize = 2048;
const WARMUP: Duration = Duration::from_secs(1);
const MEASURE: Duration = Duration::from_secs(3);

fn main() {
    println!("genwallet hot-path compare");
    println!("batch_size={BATCH_SIZE}  warmup={WARMUP:?}  measure={MEASURE:?}");
    println!();

    let prev = bench_previous();
    let new = bench_new();

    println!("{:<28} {:>14} {:>12}", "variant", "addr/s", "ns/addr");
    println!("{}", "-".repeat(56));
    print_row("previous (0.13-style)", prev);
    print_row("new      (0.14-style)", new);
    println!();

    let speedup = new / prev;
    println!(
        "speedup: new is {speedup:.3}× previous  ({:+.1}%)",
        (speedup - 1.0) * 100.0
    );
}

fn print_row(label: &str, rate: f64) {
    let ns = 1e9 / rate;
    println!("{label:<28} {rate:>14.0} {ns:>12.1}");
}

/// Previous main.rs path on k256 0.13:
/// constant-time `batch_normalize` + SEC1 `to_encoded_point` + keccak.
fn bench_previous() -> f64 {
    use k256_v013::elliptic_curve::BatchNormalize;
    use k256_v013::elliptic_curve::sec1::ToEncodedPoint;
    use k256_v013::{ProjectivePoint, SecretKey};

    let mut rng = StdRng::seed_from_u64(0xA11CE);
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = SecretKey::from_slice(&sk_bytes).unwrap_or_else(|_| {
        SecretKey::from_slice(&[1u8; 32]).unwrap()
    });

    let g = ProjectivePoint::GENERATOR;
    let mut increments = Vec::with_capacity(BATCH_SIZE);
    let mut curr_g = g;
    for _ in 0..BATCH_SIZE {
        increments.push(curr_g.to_affine());
        curr_g += g;
    }
    let step_batch_g = ProjectivePoint::from(*increments.last().unwrap());

    let mut current_point = ProjectivePoint::from(sk.public_key());
    let mut batch_points = [ProjectivePoint::IDENTITY; BATCH_SIZE];
    let mut hasher = Keccak256::new();
    let mut sink = 0u64;

    // warmup
    let start = Instant::now();
    while start.elapsed() < WARMUP {
        batch_points[0] = current_point;
        for i in 1..BATCH_SIZE {
            batch_points[i] = current_point + increments[i - 1];
        }
        let affine = ProjectivePoint::batch_normalize(&batch_points);
        for point in &affine {
            let encoded = point.to_encoded_point(false);
            hasher.update(encoded.x().unwrap());
            hasher.update(encoded.y().unwrap());
            let hash = hasher.finalize_reset();
            sink = sink.wrapping_add(hash[12] as u64);
        }
        current_point += step_batch_g;
    }
    black_box(sink);

    // measure
    let mut addresses = 0u64;
    let start = Instant::now();
    while start.elapsed() < MEASURE {
        batch_points[0] = current_point;
        for i in 1..BATCH_SIZE {
            batch_points[i] = current_point + increments[i - 1];
        }
        let affine = ProjectivePoint::batch_normalize(&batch_points);
        for point in &affine {
            let encoded = point.to_encoded_point(false);
            hasher.update(encoded.x().unwrap());
            hasher.update(encoded.y().unwrap());
            let hash = hasher.finalize_reset();
            sink = sink.wrapping_add(hash[12] as u64);
        }
        current_point += step_batch_g;
        addresses += BATCH_SIZE as u64;
    }
    black_box(sink);
    addresses as f64 / start.elapsed().as_secs_f64()
}

/// Current main.rs path on k256 0.14:
/// `batch_normalize_vartime` + `AffineCoordinates::{x,y}` + keccak.
fn bench_new() -> f64 {
    use k256::elliptic_curve::point::{AffineCoordinates, BatchNormalize};
    use k256::{ProjectivePoint, SecretKey};

    let mut rng = StdRng::seed_from_u64(0xA11CE);
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk = SecretKey::from_slice(&sk_bytes).unwrap_or_else(|_| {
        SecretKey::from_slice(&[1u8; 32]).unwrap()
    });

    let g = ProjectivePoint::GENERATOR;
    let mut increments = Vec::with_capacity(BATCH_SIZE);
    let mut curr_g = g;
    for _ in 0..BATCH_SIZE {
        increments.push(curr_g.to_affine());
        curr_g += g;
    }
    let step_batch_g = ProjectivePoint::from(*increments.last().unwrap());

    let mut current_point = ProjectivePoint::from(sk.public_key());
    let mut batch_points = [ProjectivePoint::IDENTITY; BATCH_SIZE];
    let mut hasher = Keccak256::new();
    let mut sink = 0u64;

    let start = Instant::now();
    while start.elapsed() < WARMUP {
        batch_points[0] = current_point;
        for i in 1..BATCH_SIZE {
            batch_points[i] = current_point + increments[i - 1];
        }
        let affine =
            <ProjectivePoint as BatchNormalize<_>>::batch_normalize_vartime(&batch_points);
        for point in &affine {
            hasher.update(point.x());
            hasher.update(point.y());
            let hash = hasher.finalize_reset();
            sink = sink.wrapping_add(hash[12] as u64);
        }
        current_point += step_batch_g;
    }
    black_box(sink);

    let mut addresses = 0u64;
    let start = Instant::now();
    while start.elapsed() < MEASURE {
        batch_points[0] = current_point;
        for i in 1..BATCH_SIZE {
            batch_points[i] = current_point + increments[i - 1];
        }
        let affine =
            <ProjectivePoint as BatchNormalize<_>>::batch_normalize_vartime(&batch_points);
        for point in &affine {
            hasher.update(point.x());
            hasher.update(point.y());
            let hash = hasher.finalize_reset();
            sink = sink.wrapping_add(hash[12] as u64);
        }
        current_point += step_batch_g;
        addresses += BATCH_SIZE as u64;
    }
    black_box(sink);
    addresses as f64 / start.elapsed().as_secs_f64()
}
