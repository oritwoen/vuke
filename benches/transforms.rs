use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vuke::transform::{Input, TransformType};

fn bench_sha256(c: &mut Criterion) {
    let transform = TransformType::Sha256.create();
    let input = Input::from_string("correct horse battery staple".to_string());
    let inputs = vec![input; 1000];

    c.bench_function("sha256_transform", |b| {
        b.iter(|| {
            let mut buffer = Vec::with_capacity(1000);
            transform.apply_batch(black_box(&inputs), &mut buffer);
        })
    });
}

fn bench_double_sha256(c: &mut Criterion) {
    let transform = TransformType::DoubleSha256.create();
    let input = Input::from_string("test passphrase".to_string());
    let inputs = vec![input; 1000];

    c.bench_function("double_sha256_transform", |b| {
        b.iter(|| {
            let mut buffer = Vec::with_capacity(1000);
            transform.apply_batch(black_box(&inputs), &mut buffer);
        })
    });
}

fn bench_milksad(c: &mut Criterion) {
    let transform = TransformType::Milksad.create();
    let input = Input::from_u64(1234567890);
    let inputs = vec![input; 100];

    c.bench_function("milksad_transform", |b| {
        b.iter(|| {
            let mut buffer = Vec::with_capacity(100);
            transform.apply_batch(black_box(&inputs), &mut buffer);
        })
    });
}

fn bench_direct(c: &mut Criterion) {
    let transform = TransformType::Direct.create();
    let input = Input::from_u64(42);
    let inputs = vec![input; 1000];

    c.bench_function("direct_transform", |b| {
        b.iter(|| {
            let mut buffer = Vec::with_capacity(1000);
            transform.apply_batch(black_box(&inputs), &mut buffer);
        })
    });
}

fn bench_md5(c: &mut Criterion) {
    let transform = TransformType::Md5.create();
    let input = Input::from_string("password123".to_string());
    let inputs = vec![input; 1000];

    c.bench_function("md5_transform", |b| {
        b.iter(|| {
            let mut buffer = Vec::with_capacity(1000);
            transform.apply_batch(black_box(&inputs), &mut buffer);
        })
    });
}

criterion_group!(
    benches,
    bench_sha256,
    bench_double_sha256,
    bench_milksad,
    bench_direct,
    bench_md5
);
criterion_main!(benches);
