//! MT19937-64 analyzer - brute-force search for 64-bit seeds.
//!
//! REQUIRES cascade filter - 64-bit seed space (2^64) is not exhaustively searchable.

use indicatif::ProgressBar;
use rand_mt::Mt64;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use super::{Analyzer, AnalysisConfig, AnalysisResult, AnalysisStatus};

pub struct Mt64Analyzer;

impl Analyzer for Mt64Analyzer {
    fn name(&self) -> &'static str {
        "mt64"
    }

    fn supports_mask(&self) -> bool {
        true
    }

    fn is_brute_force(&self) -> bool {
        true
    }

    fn analyze(
        &self,
        _key: &[u8; 32],
        config: &AnalysisConfig,
        progress: Option<&ProgressBar>,
    ) -> AnalysisResult {
        let Some(ref targets) = config.cascade_targets else {
            return AnalysisResult {
                analyzer: self.name(),
                status: AnalysisStatus::Unknown,
                details: Some(
                    "64-bit seed space (2^64) requires --cascade filter. \
                     Without cascade, brute-force is infeasible. \
                     Example: --cascade 5:0x15,10:0x202,20:0xd2c55".to_string()
                ),
            };
        };

        if targets.is_empty() {
            return AnalysisResult {
                analyzer: self.name(),
                status: AnalysisStatus::Unknown,
                details: Some("Cascade filter is empty".to_string()),
            };
        }

        self.analyze_cascading(targets, progress)
    }
}

impl Mt64Analyzer {
    fn analyze_cascading(
        &self,
        targets: &[(u8, u64)],
        progress: Option<&ProgressBar>,
    ) -> AnalysisResult {
        let found_seed = AtomicU64::new(0);
        let found = AtomicBool::new(false);
        let searched = AtomicU64::new(0);
        let cascade_hits = AtomicU64::new(0);
        let start_time = Instant::now();

        if let Some(pb) = progress {
            pb.set_style(indicatif::ProgressStyle::default_bar()
                .template("{spinner:.green} Searched: {pos} seeds | Rate: {per_sec} | Elapsed: {elapsed} | {msg}")
                .unwrap());
            pb.set_length(u64::MAX);
            pb.set_message("Cascade hits: 0");
        }

        let found_keys: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());

        let chunk_size = 1_000_000u64;
        let mut chunk_idx = 0u64;

        loop {
            if found.load(Ordering::Acquire) {
                break;
            }

            let start = chunk_idx.saturating_mul(chunk_size);
            let end = start.saturating_add(chunk_size - 1);

            if chunk_idx > 0 && start == 0 {
                break;
            }

            let result = self.search_chunk(
                start,
                end,
                targets,
                &found,
                &found_seed,
                &found_keys,
                &cascade_hits,
            );

            searched.fetch_add(end - start + 1, Ordering::Relaxed);

            if let Some(pb) = progress {
                pb.set_position(searched.load(Ordering::Relaxed));
                pb.set_message(format!("Cascade hits: {}", cascade_hits.load(Ordering::Relaxed)));
            }

            if result {
                break;
            }

            chunk_idx += 1;
        }

        if let Some(pb) = progress {
            pb.finish_and_clear();
        }

        let total_searched = searched.load(Ordering::Relaxed);
        let elapsed = start_time.elapsed();

        if found.load(Ordering::Acquire) {
            let seed = found_seed.load(Ordering::Acquire);
            let keys = found_keys.lock().unwrap().clone();

            let details = format_cascade_result(seed, targets, &keys, total_searched, elapsed);

            AnalysisResult {
                analyzer: self.name(),
                status: AnalysisStatus::Confirmed,
                details: Some(details),
            }
        } else {
            let target_desc: Vec<String> = targets
                .iter()
                .map(|(bits, target)| format!("P{}:0x{:x}", bits, target))
                .collect();

            AnalysisResult {
                analyzer: self.name(),
                status: AnalysisStatus::NotFound,
                details: Some(format!(
                    "searched {} seeds in {:.2}s, cascade=[{}], cascade_hits={}",
                    total_searched,
                    elapsed.as_secs_f64(),
                    target_desc.join(","),
                    cascade_hits.load(Ordering::Relaxed)
                )),
            }
        }
    }

    fn search_chunk(
        &self,
        start: u64,
        end: u64,
        targets: &[(u8, u64)],
        found: &AtomicBool,
        found_seed: &AtomicU64,
        found_keys: &Mutex<Vec<[u8; 32]>>,
        cascade_hits: &AtomicU64,
    ) -> bool {
        (start..=end).into_par_iter().find_any(|&seed| {
            if found.load(Ordering::Acquire) {
                return false;
            }

            let mut rng = Mt64::new(seed);
            let mut keys: Vec<[u8; 32]> = Vec::with_capacity(targets.len());
            let mut all_matched = true;
            let mut first_filter_passed = false;

            for (i, (bits, target)) in targets.iter().enumerate() {
                let mut key = [0u8; 32];
                rng.fill_bytes(&mut key);

                let key_u64 = u64::from_be_bytes(key[24..32].try_into().unwrap());
                let mask: u64 = if *bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                let high_bit: u64 = 1u64 << (bits - 1);
                let masked = (key_u64 & mask) | high_bit;

                if masked != *target {
                    all_matched = false;
                    break;
                }

                if i == 0 {
                    first_filter_passed = true;
                }
                keys.push(key);
            }

            if first_filter_passed && !all_matched {
                cascade_hits.fetch_add(1, Ordering::Relaxed);
            }

            if all_matched {
                found_seed.store(seed, Ordering::Release);
                found.store(true, Ordering::Release);
                if let Ok(mut fk) = found_keys.lock() {
                    *fk = keys;
                }
                return true;
            }

            false
        }).is_some()
    }
}

fn format_cascade_result(
    seed: u64,
    targets: &[(u8, u64)],
    keys: &[[u8; 32]],
    searched: u64,
    elapsed: std::time::Duration,
) -> String {
    let mut lines = vec![
        format!("seed={} (0x{:016x})", seed, seed),
        format!("searched {} seeds in {:.2}s", searched, elapsed.as_secs_f64()),
    ];

    for ((bits, target), key) in targets.iter().zip(keys.iter()) {
        lines.push(format!(
            "  P{}: target=0x{:x}, full_key={}",
            bits, target, hex::encode(key)
        ));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_mask(key: &[u8; 32], bits: u8) -> u64 {
        let key_u64 = u64::from_be_bytes(key[24..32].try_into().unwrap());
        let mask: u64 = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        let high_bit: u64 = 1u64 << (bits - 1);
        (key_u64 & mask) | high_bit
    }

    fn generate_cascade_targets(seed: u64, bit_widths: &[u8]) -> Vec<(u8, u64)> {
        let mut rng = Mt64::new(seed);
        bit_widths
            .iter()
            .map(|&bits| {
                let mut key = [0u8; 32];
                rng.fill_bytes(&mut key);
                (bits, apply_mask(&key, bits))
            })
            .collect()
    }

    #[test]
    fn test_requires_cascade() {
        let analyzer = Mt64Analyzer;
        let config = AnalysisConfig::default();
        let result = analyzer.analyze(&[0u8; 32], &config, None);

        assert_eq!(result.status, AnalysisStatus::Unknown);
        assert!(result.details.unwrap().contains("requires --cascade"));
    }

    #[test]
    fn test_rejects_empty_cascade() {
        let analyzer = Mt64Analyzer;
        let config = AnalysisConfig {
            mask_bits: None,
            cascade_targets: Some(vec![]),
        };
        let result = analyzer.analyze(&[0u8; 32], &config, None);

        assert_eq!(result.status, AnalysisStatus::Unknown);
        assert!(result.details.unwrap().contains("empty"));
    }

    #[test]
    fn test_cascade_finds_known_seed() {
        let known_seed = 12345u64;
        let targets = generate_cascade_targets(known_seed, &[5, 10, 15]);

        let config = AnalysisConfig {
            mask_bits: None,
            cascade_targets: Some(targets),
        };

        let result = Mt64Analyzer.analyze(&[0u8; 32], &config, None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.unwrap().contains(&format!("seed={}", known_seed)));
    }

    #[test]
    fn test_cascade_finds_zero_seed() {
        let known_seed = 0u64;
        let targets = generate_cascade_targets(known_seed, &[5, 10]);

        let config = AnalysisConfig {
            mask_bits: None,
            cascade_targets: Some(targets),
        };

        let result = Mt64Analyzer.analyze(&[0u8; 32], &config, None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.unwrap().contains("seed=0"));
    }

    #[test]
    fn test_cascade_sequential_keys() {
        let seed = 42u64;
        let mut rng = Mt64::new(seed);

        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        rng.fill_bytes(&mut key1);
        rng.fill_bytes(&mut key2);

        assert_ne!(key1, key2);

        let mut rng2 = Mt64::new(seed);
        let mut key1_verify = [0u8; 32];
        let mut key2_verify = [0u8; 32];
        rng2.fill_bytes(&mut key1_verify);
        rng2.fill_bytes(&mut key2_verify);

        assert_eq!(key1, key1_verify);
        assert_eq!(key2, key2_verify);
    }

    #[test]
    fn test_mask_formula() {
        let mask_bits: u8 = 5;
        let mask: u64 = (1u64 << mask_bits) - 1;
        let high_bit: u64 = 1u64 << (mask_bits - 1);

        assert_eq!(mask, 0x1f);
        assert_eq!(high_bit, 0x10);

        let full_key: u64 = 0xabcdef12345;
        let masked = (full_key & mask) | high_bit;
        assert_eq!(masked, 0x15);
    }
}
