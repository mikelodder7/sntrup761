//! Benchmarks

use criterion::{criterion_group, criterion_main, Criterion};
use sntrup761::*;

fn key_gen_bench(c: &mut Criterion) {
    c.bench_function("keygen", |b| b.iter(|| generate_key(rand::rng())));
}

fn encapsulate_bench(c: &mut Criterion) {
    let (pk, _sk) = generate_key(rand::rng());
    c.bench_function("encapsulate", |b| b.iter(|| pk.encapsulate(rand::rng())));
}

fn decapsulate_bench(c: &mut Criterion) {
    let (pk, sk) = generate_key(rand::rng());
    let (ct, _k) = pk.encapsulate(rand::rng());
    c.bench_function("decapsulate", |b| b.iter(|| sk.decapsulate(&ct)));
}

criterion_group!(benches, key_gen_bench, encapsulate_bench, decapsulate_bench);
criterion_main!(benches);
