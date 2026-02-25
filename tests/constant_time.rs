//! Dudect-style constant-time timing tests for sntrup761.
//!
//! These tests use Welch's t-test to compare timing distributions of
//! cryptographic operations on different input classes. A |t| < 4.5
//! threshold provides high confidence that no timing side channel exists.
//!
//! Run with:
//!   cargo test --release --test constant_time -- --ignored --nocapture

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sntrup761::*;
use std::hint::black_box;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SAMPLES_PER_CLASS: usize = 2000;
const WARMUP_ITERS: usize = 500;
const T_THRESHOLD: f64 = 4.5;
const TRIM_LO: f64 = 0.05; // 5th percentile
const TRIM_HI: f64 = 0.95; // 95th percentile

// ---------------------------------------------------------------------------
// Statistical helpers
// ---------------------------------------------------------------------------

/// Trims outliers below the 5th and above the 95th percentile.
fn trim_outliers(data: &[f64]) -> Vec<f64> {
    let mut sorted = data.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("NaN in timing data"));
    let lo = (sorted.len() as f64 * TRIM_LO) as usize;
    let hi = (sorted.len() as f64 * TRIM_HI) as usize;
    sorted[lo..hi].to_vec()
}

/// Computes the mean of a slice.
fn mean(data: &[f64]) -> f64 {
    let n = data.len() as f64;
    data.iter().sum::<f64>() / n
}

/// Computes the variance of a slice.
fn variance(data: &[f64]) -> f64 {
    let m = mean(data);
    let n = data.len() as f64;
    data.iter().map(|&x| (x - m) * (x - m)).sum::<f64>() / (n - 1.0)
}

/// Welch's t-test: compares two independent samples, returns t-statistic.
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let mean_a = mean(a);
    let mean_b = mean(b);
    let var_a = variance(a);
    let var_b = variance(b);
    let na = a.len() as f64;
    let nb = b.len() as f64;
    let se = (var_a / na + var_b / nb).sqrt();
    if se == 0.0 {
        return 0.0;
    }
    (mean_a - mean_b) / se
}

// ---------------------------------------------------------------------------
// Generic measurement harness
// ---------------------------------------------------------------------------

/// Interleaved timing measurement following the dudect methodology.
///
/// Randomly alternates between class A and class B measurements to prevent
/// systematic cache/frequency bias. Returns true if the test passes (|t| < threshold).
fn measure_interleaved<A, B, FA, FB>(
    name: &str,
    inputs_a: &[A],
    inputs_b: &[B],
    run_a: FA,
    run_b: FB,
) -> bool
where
    FA: Fn(&A),
    FB: Fn(&B),
{
    assert!(inputs_a.len() >= SAMPLES_PER_CLASS);
    assert!(inputs_b.len() >= SAMPLES_PER_CLASS);

    // Build shuffled schedule: (class, index) pairs
    let total = SAMPLES_PER_CLASS * 2;
    let mut schedule: Vec<(bool, usize)> = Vec::with_capacity(total);
    for i in 0..SAMPLES_PER_CLASS {
        schedule.push((true, i)); // class A
        schedule.push((false, i)); // class B
    }

    // Fisher-Yates shuffle with seeded RNG for reproducibility
    let mut rng = ChaCha8Rng::seed_from_u64(0xDEAD_BEEF_CAFE_1234);
    for i in (1..schedule.len()).rev() {
        let j = rng.random_range(0..=i);
        schedule.swap(i, j);
    }

    // Warmup: cycle through both classes
    for i in 0..WARMUP_ITERS {
        let idx = i % inputs_a.len().min(inputs_b.len());
        run_a(black_box(&inputs_a[idx]));
        run_b(black_box(&inputs_b[idx]));
    }

    // Measure
    let mut times_a = Vec::with_capacity(SAMPLES_PER_CLASS);
    let mut times_b = Vec::with_capacity(SAMPLES_PER_CLASS);

    for &(is_class_a, idx) in &schedule {
        if is_class_a {
            let start = Instant::now();
            run_a(black_box(&inputs_a[idx]));
            let elapsed = start.elapsed().as_nanos() as f64;
            times_a.push(black_box(elapsed));
        } else {
            let start = Instant::now();
            run_b(black_box(&inputs_b[idx]));
            let elapsed = start.elapsed().as_nanos() as f64;
            times_b.push(black_box(elapsed));
        }
    }

    // Trim outliers
    let trimmed_a = trim_outliers(&times_a);
    let trimmed_b = trim_outliers(&times_b);

    // Compute statistics
    let mean_a = mean(&trimmed_a);
    let mean_b = mean(&trimmed_b);
    let std_a = variance(&trimmed_a).sqrt();
    let std_b = variance(&trimmed_b).sqrt();
    let t = welch_t(&trimmed_a, &trimmed_b);
    let pass = t.abs() < T_THRESHOLD;

    eprintln!("--- {name} ---");
    eprintln!(
        "  Class A: mean = {mean_a:.1} ns, stddev = {std_a:.1} ns (n = {})",
        trimmed_a.len()
    );
    eprintln!(
        "  Class B: mean = {mean_b:.1} ns, stddev = {std_b:.1} ns (n = {})",
        trimmed_b.len()
    );
    eprintln!("  t-statistic = {t:.4}  (threshold = +/-{T_THRESHOLD})");
    eprintln!("  Result: {}", if pass { "PASS" } else { "FAIL" });
    eprintln!();

    pass
}

// ---------------------------------------------------------------------------
// Helper: generate a keypair and valid ciphertexts from a seed range
// ---------------------------------------------------------------------------

fn make_seed(base: u8, index: usize) -> [u8; 32] {
    let mut seed = [base; 32];
    let idx_bytes = (index as u64).to_le_bytes();
    seed[..8].copy_from_slice(&idx_bytes);
    seed
}

// ---------------------------------------------------------------------------
// Test 1: decap valid vs invalid (bit-flipped) ciphertexts
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn timing_decap_valid_vs_invalid() {
    // Generate a fixed keypair
    let (pk, sk) = generate_key_from_seed([0x11; 32]);

    // Class A: valid ciphertexts
    let valid_cts: Vec<Ciphertext> = (0..SAMPLES_PER_CLASS)
        .map(|i| {
            let seed = make_seed(0xAA, i);
            let (ct, _ss) = pk.encapsulate_deterministic(seed);
            ct
        })
        .collect();

    // Class B: corrupted ciphertexts (bit-flip at multiple positions)
    let invalid_cts: Vec<Ciphertext> = (0..SAMPLES_PER_CLASS)
        .map(|i| {
            let seed = make_seed(0xBB, i);
            let (ct, _ss) = pk.encapsulate_deterministic(seed);
            let mut bytes = [0u8; CIPHERTEXT_SIZE];
            bytes.copy_from_slice(ct.as_ref());
            // Corrupt at bytes 0, 100, 500, 900
            bytes[0] ^= 0xFF;
            bytes[100] ^= 0x42;
            bytes[500] ^= 0x13;
            bytes[900] ^= 0x7E;
            Ciphertext::from(bytes)
        })
        .collect();

    let pass = measure_interleaved(
        "decap valid vs invalid (bit-flipped)",
        &valid_cts,
        &invalid_cts,
        |ct| {
            let _ = black_box(sk.decapsulate(black_box(ct)));
        },
        |ct| {
            let _ = black_box(sk.decapsulate(black_box(ct)));
        },
    );

    assert!(
        pass,
        "Timing difference detected between valid and invalid ciphertexts!"
    );
}

// ---------------------------------------------------------------------------
// Test 2: decap valid vs garbage ciphertexts
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn timing_decap_valid_vs_garbage() {
    let (pk, sk) = generate_key_from_seed([0x22; 32]);

    // Class A: valid ciphertexts
    let valid_cts: Vec<Ciphertext> = (0..SAMPLES_PER_CLASS)
        .map(|i| {
            let seed = make_seed(0xCC, i);
            let (ct, _ss) = pk.encapsulate_deterministic(seed);
            ct
        })
        .collect();

    // Class B: random garbage ciphertexts (different patterns)
    let garbage_cts: Vec<Ciphertext> = (0..SAMPLES_PER_CLASS)
        .map(|i| {
            let pattern = ((i % 256) as u8).wrapping_add(0x10);
            let mut bytes = [pattern; CIPHERTEXT_SIZE];
            // Add some variation based on index
            let idx_bytes = (i as u64).to_le_bytes();
            bytes[..8].copy_from_slice(&idx_bytes);
            Ciphertext::from(bytes)
        })
        .collect();

    let pass = measure_interleaved(
        "decap valid vs garbage",
        &valid_cts,
        &garbage_cts,
        |ct| {
            let _ = black_box(sk.decapsulate(black_box(ct)));
        },
        |ct| {
            let _ = black_box(sk.decapsulate(black_box(ct)));
        },
    );

    assert!(
        pass,
        "Timing difference detected between valid and garbage ciphertexts!"
    );
}

// ---------------------------------------------------------------------------
// Test 3: decap different valid ciphertexts (two seed groups)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn timing_decap_different_valid() {
    let (pk, sk) = generate_key_from_seed([0x33; 32]);

    // Class A: valid CTs from seed group A
    let cts_a: Vec<Ciphertext> = (0..SAMPLES_PER_CLASS)
        .map(|i| {
            let seed = make_seed(0xDD, i);
            let (ct, _ss) = pk.encapsulate_deterministic(seed);
            ct
        })
        .collect();

    // Class B: valid CTs from seed group B
    let cts_b: Vec<Ciphertext> = (0..SAMPLES_PER_CLASS)
        .map(|i| {
            let seed = make_seed(0xEE, i);
            let (ct, _ss) = pk.encapsulate_deterministic(seed);
            ct
        })
        .collect();

    let pass = measure_interleaved(
        "decap different valid CTs (group A vs group B)",
        &cts_a,
        &cts_b,
        |ct| {
            let _ = black_box(sk.decapsulate(black_box(ct)));
        },
        |ct| {
            let _ = black_box(sk.decapsulate(black_box(ct)));
        },
    );

    assert!(
        pass,
        "Timing difference detected between different valid ciphertexts!"
    );
}

// ---------------------------------------------------------------------------
// Test 4: keygen different seeds
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn timing_keygen_different_seeds() {
    // Class A: seeds from group A
    let seeds_a: Vec<[u8; 32]> = (0..SAMPLES_PER_CLASS).map(|i| make_seed(0xA0, i)).collect();

    // Class B: seeds from group B
    let seeds_b: Vec<[u8; 32]> = (0..SAMPLES_PER_CLASS).map(|i| make_seed(0xB0, i)).collect();

    let pass = measure_interleaved(
        "keygen different seeds (group A vs group B)",
        &seeds_a,
        &seeds_b,
        |seed| {
            let _ = black_box(generate_key_from_seed(black_box(*seed)));
        },
        |seed| {
            let _ = black_box(generate_key_from_seed(black_box(*seed)));
        },
    );

    assert!(
        pass,
        "Timing difference detected between different keygen seeds!"
    );
}

// ---------------------------------------------------------------------------
// Test 5: encap different seeds
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn timing_encap_different_seeds() {
    let (pk, _sk) = generate_key_from_seed([0x55; 32]);

    // Class A: encapsulation seeds from group A
    let seeds_a: Vec<[u8; 32]> = (0..SAMPLES_PER_CLASS).map(|i| make_seed(0xC0, i)).collect();

    // Class B: encapsulation seeds from group B
    let seeds_b: Vec<[u8; 32]> = (0..SAMPLES_PER_CLASS).map(|i| make_seed(0xD0, i)).collect();

    let pass = measure_interleaved(
        "encap different seeds (group A vs group B)",
        &seeds_a,
        &seeds_b,
        |seed| {
            let _ = black_box(pk.encapsulate_deterministic(black_box(*seed)));
        },
        |seed| {
            let _ = black_box(pk.encapsulate_deterministic(black_box(*seed)));
        },
    );

    assert!(
        pass,
        "Timing difference detected between different encap seeds!"
    );
}
