use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vuke::derive::KeyDeriver;

fn bench_key_derivation(c: &mut Criterion) {
    let deriver = KeyDeriver::new();
    let private_key =
        hex::decode("c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")
            .unwrap()
            .try_into()
            .unwrap();

    c.bench_function("derive_addresses", |b| {
        b.iter(|| {
            deriver.derive(black_box(&private_key));
        })
    });
}

fn bench_batch_derivation(c: &mut Criterion) {
    let deriver = KeyDeriver::new();
    let private_key =
        hex::decode("c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")
            .unwrap()
            .try_into()
            .unwrap();
    let keys: Vec<[u8; 32]> = (0..100).map(|_| private_key).collect();

    c.bench_function("derive_batch_100", |b| {
        b.iter(|| {
            for key in black_box(&keys) {
                deriver.derive(key);
            }
        })
    });
}

criterion_group!(benches, bench_key_derivation, bench_batch_derivation);
criterion_main!(benches);
