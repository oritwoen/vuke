//! Benchmark for transform performance.

use anyhow::Result;
use rayon::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::transform::{Input, TransformType};

fn benchmark_name(transform_type: &TransformType) -> String {
    match transform_type {
        TransformType::Direct => "direct".to_string(),
        TransformType::Sha256 => "sha256".to_string(),
        TransformType::DoubleSha256 => "double_sha256".to_string(),
        TransformType::Md5 => "md5".to_string(),
        TransformType::Milksad => "milksad".to_string(),
        TransformType::Mt64 => "mt64".to_string(),
        TransformType::Armory => "armory".to_string(),
        TransformType::Multibit => "multibit".to_string(),
        TransformType::Electrum { for_change } => {
            if *for_change {
                "electrum:change".to_string()
            } else {
                "electrum:receive".to_string()
            }
        }
        TransformType::Lcg { variant, endian } => {
            let variant_name = variant.map(|v| v.name).unwrap_or("all");
            format!("lcg:{}:{}", variant_name, endian.as_str())
        }
        TransformType::Xorshift { variant } => {
            let variant_name = variant.map(|v| v.name()).unwrap_or("all");
            format!("xorshift:{}", variant_name)
        }
        TransformType::Sha256Chain {
            variant,
            chain_depth,
        } => {
            let variant_name = variant.map(|v| v.name()).unwrap_or("all");
            format!("sha256_chain:{}:depth={}", variant_name, chain_depth)
        }
        TransformType::Bitimage {
            path,
            passphrase,
            passphrase_wordlist,
            derive_count,
        } => format!(
            "bitimage:path={}:passphrase={}:wordlist={}:derive_count={}",
            fingerprint(path),
            fingerprint(passphrase),
            passphrase_wordlist
                .as_ref()
                .map(|path| fingerprint(&path.display().to_string()))
                .unwrap_or_else(|| "none".to_string()),
            derive_count
        ),
    }
}

fn fingerprint(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..6])
}

fn format_benchmark_json(
    transform_type: &TransformType,
    speed: u64,
    count: u64,
    duration: f64,
) -> String {
    let transform_name = benchmark_name(transform_type);

    json!({
        "name": transform_name,
        "ops_per_sec": speed,
        "total_ops": count,
        "duration_secs": duration,
    })
    .to_string()
}

/// Run standardized benchmark for a transform.
pub fn run_benchmark(transform_type: TransformType, json: bool) -> Result<()> {
    if !json {
        println!("Running Benchmark for {:?}...", transform_type);
        println!("Time: 2s warmup + 5s measure (approx)");
    }

    let transform = transform_type.create();

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
            "{}",
            format_benchmark_json(&transform_type, speed as u64, count, duration)
        );
    } else {
        println!("------------------------------------------------");
        println!("Result: {:.2} Million Inputs/sec", speed / 1_000_000.0);
        println!("Total:  {} inputs in {:.2}s", count, duration);
        println!("------------------------------------------------");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{benchmark_name, format_benchmark_json};

    use crate::lcg::{LcgEndian, GLIBC};
    use crate::transform::TransformType;

    #[test]
    fn benchmark_json_keeps_parameterized_transform_details() {
        let transform_type = TransformType::Lcg {
            variant: Some(GLIBC),
            endian: LcgEndian::Big,
        };

        let output = format_benchmark_json(&transform_type, 123, 456, 7.5);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["name"].as_str(), Some("lcg:glibc:be"));
    }

    #[test]
    fn benchmark_json_redacts_bitimage_secrets() {
        let transform_type = TransformType::Bitimage {
            path: "C:\\keys\\\"set\"\n.txt".into(),
            passphrase: "word\"list\\seed\t".into(),
            passphrase_wordlist: None,
            derive_count: 2,
        };

        let output = format_benchmark_json(&transform_type, 1, 2, 3.0);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let name = parsed["name"].as_str().unwrap();

        assert_eq!(name, benchmark_name(&transform_type));
        assert!(name.contains("bitimage:path="));
        assert!(name.contains(":passphrase="));
        assert!(name.contains(":wordlist=none:derive_count=2"));
        assert!(!name.contains("word\"list\\seed\t"));
        assert!(!name.contains("C:\\keys\\\"set\"\n.txt"));
    }
}
