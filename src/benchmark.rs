//! Benchmark for transform performance.

use anyhow::Result;
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::transform::{
    ArmoryTransform, DirectTransform, DoubleSha256Transform, Input, Md5Transform,
    MilksadTransform, Sha256Transform, Transform, TransformType,
};

/// Run standardized benchmark for a transform.
pub fn run_benchmark(transform_type: TransformType, json: bool) -> Result<()> {
    if !json {
        println!("Running Benchmark for {:?}...", transform_type);
        println!("Time: 2s warmup + 5s measure (approx)");
    }

    let transform = create_transform(transform_type);

    // Prepare test data
    let input = Input::from_u64(1234567890);
    let inputs = vec![input; 1000];
    let mut buffer = Vec::with_capacity(1000 * 4);

    // Warmup phase
    let warmup = Instant::now();
    while warmup.elapsed().as_secs() < 2 {
        buffer.clear();
        transform.apply_batch(&inputs, &mut buffer);
    }

    // Measurement phase
    let start = Instant::now();
    let counter = AtomicU64::new(0);

    let pool = rayon::ThreadPoolBuilder::new().build()?;

    pool.install(|| {
        let start_inner = Instant::now();

        (0..500_000).into_par_iter().for_each(|_| {
            if start_inner.elapsed().as_secs() >= 5 {
                return;
            }

            let mut local_buf = Vec::with_capacity(4000);
            transform.apply_batch(&inputs, &mut local_buf);
            counter.fetch_add(inputs.len() as u64, Ordering::Relaxed);
        });
    });

    let count = counter.load(Ordering::Relaxed);
    let duration = start.elapsed().as_secs_f64();
    let speed = count as f64 / duration;

    if json {
        println!(
            "{{ \"name\": \"{:?}\", \"ops_per_sec\": {}, \"total_ops\": {}, \"duration_secs\": {} }}",
            transform_type, speed as u64, count, duration
        );
    } else {
        println!("------------------------------------------------");
        println!("Result: {:.2} Million Inputs/sec", speed / 1_000_000.0);
        println!("Total:  {} inputs in {:.2}s", count, duration);
        println!("------------------------------------------------");
    }

    Ok(())
}

fn create_transform(t: TransformType) -> Box<dyn Transform> {
    match t {
        TransformType::Direct => Box::new(DirectTransform),
        TransformType::Sha256 => Box::new(Sha256Transform),
        TransformType::DoubleSha256 => Box::new(DoubleSha256Transform),
        TransformType::Md5 => Box::new(Md5Transform),
        TransformType::Milksad => Box::new(MilksadTransform),
        TransformType::Armory => Box::new(ArmoryTransform::new()),
    }
}
