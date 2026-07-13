//! Focused investigation: sequential +G vs precomputed increment table.
//!
//!   cargo bench --bench hotpath_probe

use std::hint::black_box;
use std::time::{Duration, Instant};

use k256::elliptic_curve::point::{AffineCoordinates, BatchNormalize};
use k256::{AffinePoint, ProjectivePoint, SecretKey};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha3::{Digest, Keccak256};

const WARMUP: Duration = Duration::from_millis(400);
const MEASURE: Duration = Duration::from_secs(3);
const PAIRS: usize = 12;
const BATCH: usize = 2048;

fn main() {
    let _ = full_increments(BATCH);
    let _ = full_sequential(BATCH);

    println!("=== sequential +G investigation ===");
    println!("pairs={PAIRS}  measure={MEASURE:?}  warmup={WARMUP:?}  batch={BATCH}");
    println!("(odd pairs run sequential first to reduce thermal bias)\n");

    println!("--- full pipeline (EC build + normalize + keccak) ---\n");
    ab_compare(
        "increments (current)",
        "sequential +G",
        || full_increments(BATCH),
        || full_sequential(BATCH),
    );

    println!("\n--- EC only (build + batch_normalize_vartime, no keccak) ---\n");
    ab_compare(
        "increments EC",
        "sequential EC",
        || ec_increments(BATCH),
        || ec_sequential(BATCH),
    );

    println!("\n--- keccak only (repeatability check) ---\n");
    let aff = sample_affine(BATCH);
    ab_compare(
        "keccak A",
        "keccak B",
        || keccak_only(&aff),
        || keccak_only(&aff),
    );

    println!("\n--- increment walk direction (cache probe) ---\n");
    ab_compare(
        "incs forward",
        "incs reverse fill",
        || full_increments(BATCH),
        || full_increments_reversed(BATCH),
    );

    println!("\n--- batch-size sensitivity (full pipeline, 5 alternating pairs) ---\n");
    println!(
        "{:<10} {:>12} {:>12} {:>9}",
        "batch", "increments", "sequential", "seq/inc"
    );
    println!("{}", "-".repeat(48));
    for bs in [256usize, 512, 1024, 2048, 4096] {
        let mut inc = Vec::new();
        let mut seq = Vec::new();
        for i in 0..5 {
            if i % 2 == 0 {
                inc.push(full_increments(bs));
                seq.push(full_sequential(bs));
            } else {
                seq.push(full_sequential(bs));
                inc.push(full_increments(bs));
            }
        }
        inc.sort_by(|a, b| a.partial_cmp(b).unwrap());
        seq.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let im = inc[2];
        let sm = seq[2];
        println!("{bs:<10} {im:>12.0} {sm:>12.0} {:>8.3}×", sm / im);
    }
}

fn ab_compare(
    name_a: &str,
    name_b: &str,
    mut run_a: impl FnMut() -> f64,
    mut run_b: impl FnMut() -> f64,
) {
    let mut a_rates = Vec::with_capacity(PAIRS);
    let mut b_rates = Vec::with_capacity(PAIRS);
    let mut b_wins = 0usize;

    println!("{:<6} {:>12} {:>12} {:>9}", "pair", name_a, name_b, "b/a");
    println!("{}", "-".repeat(44));

    for i in 0..PAIRS {
        let (a, b) = if i % 2 == 0 {
            let a = run_a();
            let b = run_b();
            (a, b)
        } else {
            let b = run_b();
            let a = run_a();
            (a, b)
        };
        a_rates.push(a);
        b_rates.push(b);
        if b > a {
            b_wins += 1;
        }
        println!("{i:<6} {a:>12.0} {b:>12.0} {:>8.3}×", b / a);
    }

    let (a_med, a_mean, a_sd) = stats(&a_rates);
    let (b_med, b_mean, b_sd) = stats(&b_rates);
    println!();
    println!(
        "{name_a}: median={a_med:.0}  mean={a_mean:.0}  sd={a_sd:.0} ({:.2}%)",
        100.0 * a_sd / a_mean
    );
    println!(
        "{name_b}: median={b_med:.0}  mean={b_mean:.0}  sd={b_sd:.0} ({:.2}%)",
        100.0 * b_sd / b_mean
    );
    println!(
        "median speedup: {:.3}× ({:+.2}%)",
        b_med / a_med,
        (b_med / a_med - 1.0) * 100.0
    );
    println!(
        "mean speedup:   {:.3}× ({:+.2}%)",
        b_mean / a_mean,
        (b_mean / a_mean - 1.0) * 100.0
    );
    println!(
        "{name_b} faster in {b_wins}/{PAIRS} pairs ({:.0}%)",
        100.0 * b_wins as f64 / PAIRS as f64
    );
}

fn stats(xs: &[f64]) -> (f64, f64, f64) {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = v[v.len() / 2];
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / v.len() as f64;
    (med, mean, var.sqrt())
}

fn timed(mut body: impl FnMut() -> u64) -> f64 {
    let t0 = Instant::now();
    let mut w = 0u64;
    while t0.elapsed() < WARMUP {
        w = w.wrapping_add(body());
    }
    black_box(w);

    let mut n = 0u64;
    let t0 = Instant::now();
    while t0.elapsed() < MEASURE {
        n = n.wrapping_add(body());
    }
    black_box(n);
    n as f64 / t0.elapsed().as_secs_f64()
}

fn make_start() -> ProjectivePoint {
    let mut rng = StdRng::seed_from_u64(0xA11CE);
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    let sk =
        SecretKey::from_slice(&b).unwrap_or_else(|_| SecretKey::from_slice(&[1u8; 32]).unwrap());
    ProjectivePoint::from(sk.public_key())
}

fn build_increments(batch: usize) -> (Vec<AffinePoint>, ProjectivePoint) {
    let g = ProjectivePoint::GENERATOR;
    let mut incs = Vec::with_capacity(batch);
    let mut cur = g;
    for _ in 0..batch {
        incs.push(cur.to_affine());
        cur += g;
    }
    let step = ProjectivePoint::from(*incs.last().unwrap());
    (incs, step)
}

fn sample_affine(batch: usize) -> Vec<AffinePoint> {
    let mut cur = make_start();
    let g = AffinePoint::GENERATOR;
    let mut batch_pts = vec![ProjectivePoint::IDENTITY; batch];
    for slot in &mut batch_pts {
        *slot = cur;
        cur += g;
    }
    <ProjectivePoint as BatchNormalize<_>>::batch_normalize_vartime(batch_pts.as_slice())
}

fn full_increments(batch: usize) -> f64 {
    let mut current = make_start();
    let (incs, step) = build_increments(batch);
    let mut points = vec![ProjectivePoint::IDENTITY; batch];
    let mut hasher = Keccak256::new();
    let mut sink = 0u64;

    timed(|| {
        points[0] = current;
        for i in 1..batch {
            points[i] = current + incs[i - 1];
        }
        let aff =
            <ProjectivePoint as BatchNormalize<_>>::batch_normalize_vartime(points.as_slice());
        for p in &aff {
            hasher.update(p.x());
            hasher.update(p.y());
            sink = sink.wrapping_add(hasher.finalize_reset()[12] as u64);
        }
        current += step;
        black_box(sink);
        batch as u64
    })
}

fn full_increments_reversed(batch: usize) -> f64 {
    let mut current = make_start();
    let (incs, step) = build_increments(batch);
    let mut points = vec![ProjectivePoint::IDENTITY; batch];
    let mut hasher = Keccak256::new();
    let mut sink = 0u64;

    timed(|| {
        points[0] = current;
        for i in (1..batch).rev() {
            points[i] = current + incs[i - 1];
        }
        let aff =
            <ProjectivePoint as BatchNormalize<_>>::batch_normalize_vartime(points.as_slice());
        for p in &aff {
            hasher.update(p.x());
            hasher.update(p.y());
            sink = sink.wrapping_add(hasher.finalize_reset()[12] as u64);
        }
        current += step;
        black_box(sink);
        batch as u64
    })
}

fn full_sequential(batch: usize) -> f64 {
    let mut current = make_start();
    let g = AffinePoint::GENERATOR;
    let step = {
        let mut p = ProjectivePoint::IDENTITY;
        for _ in 0..batch {
            p += g;
        }
        p
    };
    let mut points = vec![ProjectivePoint::IDENTITY; batch];
    let mut hasher = Keccak256::new();
    let mut sink = 0u64;

    timed(|| {
        let mut p = current;
        for slot in &mut points {
            *slot = p;
            p += g;
        }
        let aff =
            <ProjectivePoint as BatchNormalize<_>>::batch_normalize_vartime(points.as_slice());
        for pt in &aff {
            hasher.update(pt.x());
            hasher.update(pt.y());
            sink = sink.wrapping_add(hasher.finalize_reset()[12] as u64);
        }
        current += step;
        black_box(sink);
        batch as u64
    })
}

fn ec_increments(batch: usize) -> f64 {
    let mut current = make_start();
    let (incs, step) = build_increments(batch);
    let mut points = vec![ProjectivePoint::IDENTITY; batch];
    let mut sink = 0u64;

    timed(|| {
        points[0] = current;
        for i in 1..batch {
            points[i] = current + incs[i - 1];
        }
        let aff =
            <ProjectivePoint as BatchNormalize<_>>::batch_normalize_vartime(points.as_slice());
        sink = sink.wrapping_add(aff[0].x().as_slice()[0] as u64);
        current += step;
        black_box(sink);
        batch as u64
    })
}

fn ec_sequential(batch: usize) -> f64 {
    let mut current = make_start();
    let g = AffinePoint::GENERATOR;
    let step = {
        let mut p = ProjectivePoint::IDENTITY;
        for _ in 0..batch {
            p += g;
        }
        p
    };
    let mut points = vec![ProjectivePoint::IDENTITY; batch];
    let mut sink = 0u64;

    timed(|| {
        let mut p = current;
        for slot in &mut points {
            *slot = p;
            p += g;
        }
        let aff =
            <ProjectivePoint as BatchNormalize<_>>::batch_normalize_vartime(points.as_slice());
        sink = sink.wrapping_add(aff[0].x().as_slice()[0] as u64);
        current += step;
        black_box(sink);
        batch as u64
    })
}

fn keccak_only(aff: &[AffinePoint]) -> f64 {
    let mut hasher = Keccak256::new();
    let mut sink = 0u64;
    timed(|| {
        for p in aff {
            hasher.update(p.x());
            hasher.update(p.y());
            sink = sink.wrapping_add(hasher.finalize_reset()[12] as u64);
        }
        black_box(sink);
        aff.len() as u64
    })
}
