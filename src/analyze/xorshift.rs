//! Xorshift analyzer - brute-force search for xorshift PRNG seeds.
//!
//! All variants require cascade filter due to 64-bit seed space.
//! For 128-bit state variants, we assume seed_low=0 (reduced space).

use indicatif::ProgressBar;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use crate::xorshift::{XorshiftRng, XorshiftVariant, ALL_VARIANTS};
use super::{AnalysisConfig, AnalysisResult, AnalysisStatus, Analyzer};

pub struct XorshiftAnalyzer {
    variant: Option<XorshiftVariant>,
}

impl XorshiftAnalyzer {
    pub fn new() -> Self {
        Self { variant: None }
    }

    pub fn with_variant(variant: XorshiftVariant) -> Self {
        Self {
            variant: Some(variant),
        }
    }

    fn analyze_variant(
        &self,
        variant: XorshiftVariant,
        targets: &[(u8, u64)],
        progress: Option<&ProgressBar>,
    ) -> Option<AnalysisResult> {
        let found_seed = AtomicU64::new(0);
        let found = AtomicBool::new(false);
        let searched = AtomicU64::new(0);
        let cascade_hits = AtomicU64::new(0);
        let start_time = Instant::now();

        if let Some(pb) = progress {
            pb.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template("{spinner:.green} {msg} | Searched: {pos} seeds | Rate: {per_sec} | Elapsed: {elapsed}")
                    .unwrap(),
            );
            pb.set_length(u64::MAX);
            pb.set_message(format!("xorshift:{}", variant.name()));
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

            if end < start || start == u64::MAX {
                break;
            }

            let result = self.search_chunk(
                start,
                end,
                variant,
                targets,
                &found,
                &found_seed,
                &found_keys,
                &cascade_hits,
            );

            searched.fetch_add(end - start + 1, Ordering::Relaxed);

            if let Some(pb) = progress {
                pb.set_position(searched.load(Ordering::Relaxed));
                pb.set_message(format!("xorshift:{} | Cascade hits: {}", variant.name(), cascade_hits.load(Ordering::Relaxed)));
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
        let total_cascade_hits = cascade_hits.load(Ordering::Relaxed);
        let elapsed = start_time.elapsed();

        if found.load(Ordering::Acquire) {
            let seed = found_seed.load(Ordering::Acquire);
            let keys = found_keys.lock().unwrap().clone();

            let details = format_cascade_result(seed, variant, targets, &keys, total_searched, total_cascade_hits, elapsed);

            Some(AnalysisResult {
                analyzer: "xorshift",
                status: AnalysisStatus::Confirmed,
                details: Some(details),
            })
        } else {
            None
        }
    }

    fn search_chunk(
        &self,
        start: u64,
        end: u64,
        variant: XorshiftVariant,
        targets: &[(u8, u64)],
        found: &AtomicBool,
        found_seed: &AtomicU64,
        found_keys: &Mutex<Vec<[u8; 32]>>,
        cascade_hits: &AtomicU64,
    ) -> bool {
        (start..=end)
            .into_par_iter()
            .find_any(|&seed| {
                if found.load(Ordering::Acquire) {
                    return false;
                }

                let (all_matched, first_filter_passed, keys) = match variant {
                    XorshiftVariant::Xorshift64 => {
                        check_seed_with_rng(crate::xorshift::Xorshift64::new(seed), targets)
                    }
                    XorshiftVariant::Xorshift128 => {
                        check_seed_with_rng(crate::xorshift::Xorshift128::new(seed), targets)
                    }
                    XorshiftVariant::Xorshift128Plus => {
                        check_seed_with_rng(crate::xorshift::Xorshift128Plus::new(seed), targets)
                    }
                    XorshiftVariant::Xoroshiro128StarStar => {
                        check_seed_with_rng(crate::xorshift::Xoroshiro128StarStar::new(seed), targets)
                    }
                };

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
            })
            .is_some()
    }
}

fn check_mask(key: &[u8; 32], bits: u8, target: u64) -> bool {
    if bits == 0 {
        return false;
    }
    let key_u64 = u64::from_be_bytes(key[24..32].try_into().unwrap());
    let mask: u64 = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let high_bit: u64 = 1u64 << (bits - 1);
    let masked = (key_u64 & mask) | high_bit;
    masked == target
}

fn check_seed_with_rng<R: XorshiftRng>(mut rng: R, targets: &[(u8, u64)]) -> (bool, bool, Vec<[u8; 32]>) {
    let mut keys: Vec<[u8; 32]> = Vec::with_capacity(targets.len());
    let mut all_matched = true;
    let mut first_filter_passed = false;

    for (i, (bits, target)) in targets.iter().enumerate() {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);

        if !check_mask(&key, *bits, *target) {
            all_matched = false;
            break;
        }

        if i == 0 {
            first_filter_passed = true;
        }
        keys.push(key);
    }

    (all_matched, first_filter_passed, keys)
}

fn format_cascade_result(
    seed: u64,
    variant: XorshiftVariant,
    targets: &[(u8, u64)],
    keys: &[[u8; 32]],
    searched: u64,
    cascade_hits: u64,
    elapsed: std::time::Duration,
) -> String {
    let mut lines = vec![
        format!("variant={}, seed={} (0x{:016x})", variant.name(), seed, seed),
        format!("searched {} seeds in {:.2}s, cascade_hits={}", searched, elapsed.as_secs_f64(), cascade_hits),
    ];

    for ((bits, target), key) in targets.iter().zip(keys.iter()) {
        lines.push(format!(
            "  P{}: target=0x{:x}, full_key={}",
            bits,
            target,
            hex::encode(key)
        ));
    }

    lines.join("\n")
}

impl Default for XorshiftAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for XorshiftAnalyzer {
    fn name(&self) -> &'static str {
        "xorshift"
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
                    "64-bit seed space requires --cascade filter. \
                     Example: --cascade 5:0x15,10:0x202,20:0xd2c55"
                        .to_string(),
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

        let variants: Vec<XorshiftVariant> = match self.variant {
            Some(v) => vec![v],
            None => ALL_VARIANTS.to_vec(),
        };

        for variant in &variants {
            if let Some(result) = self.analyze_variant(*variant, targets, progress) {
                return result;
            }
        }

        let variant_names: Vec<&str> = variants.iter().map(|v| v.name()).collect();
        let target_desc: Vec<String> = targets
            .iter()
            .map(|(bits, target)| format!("P{}:0x{:x}", bits, target))
            .collect();

        AnalysisResult {
            analyzer: self.name(),
            status: AnalysisStatus::NotFound,
            details: Some(format!(
                "checked variants=[{}], cascade=[{}]",
                variant_names.join(", "),
                target_desc.join(",")
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_mask(key: &[u8; 32], bits: u8) -> u64 {
        assert!(bits > 0, "bits must be > 0");
        let key_u64 = u64::from_be_bytes(key[24..32].try_into().unwrap());
        let mask: u64 = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let high_bit: u64 = 1u64 << (bits - 1);
        (key_u64 & mask) | high_bit
    }

    fn generate_cascade_targets(seed: u64, variant: XorshiftVariant, bit_widths: &[u8]) -> Vec<(u8, u64)> {
        let mut targets = Vec::new();

        match variant {
            XorshiftVariant::Xorshift64 => {
                let mut rng = crate::xorshift::Xorshift64::new(seed);
                for &bits in bit_widths {
                    let mut key = [0u8; 32];
                    rng.fill_bytes(&mut key);
                    targets.push((bits, apply_mask(&key, bits)));
                }
            }
            XorshiftVariant::Xorshift128 => {
                let mut rng = crate::xorshift::Xorshift128::new(seed);
                for &bits in bit_widths {
                    let mut key = [0u8; 32];
                    rng.fill_bytes(&mut key);
                    targets.push((bits, apply_mask(&key, bits)));
                }
            }
            XorshiftVariant::Xorshift128Plus => {
                let mut rng = crate::xorshift::Xorshift128Plus::new(seed);
                for &bits in bit_widths {
                    let mut key = [0u8; 32];
                    rng.fill_bytes(&mut key);
                    targets.push((bits, apply_mask(&key, bits)));
                }
            }
            XorshiftVariant::Xoroshiro128StarStar => {
                let mut rng = crate::xorshift::Xoroshiro128StarStar::new(seed);
                for &bits in bit_widths {
                    let mut key = [0u8; 32];
                    rng.fill_bytes(&mut key);
                    targets.push((bits, apply_mask(&key, bits)));
                }
            }
        }

        targets
    }

    #[test]
    fn test_requires_cascade() {
        let analyzer = XorshiftAnalyzer::new();
        let config = AnalysisConfig::default();
        let result = analyzer.analyze(&[0u8; 32], &config, None);

        assert_eq!(result.status, AnalysisStatus::Unknown);
        assert!(result.details.unwrap().contains("requires --cascade"));
    }

    #[test]
    fn test_rejects_empty_cascade() {
        let analyzer = XorshiftAnalyzer::new();
        let config = AnalysisConfig {
            mask_bits: None,
            cascade_targets: Some(vec![]),
        };
        let result = analyzer.analyze(&[0u8; 32], &config, None);

        assert_eq!(result.status, AnalysisStatus::Unknown);
        assert!(result.details.unwrap().contains("empty"));
    }

    #[test]
    fn test_cascade_finds_known_xorshift64_seed() {
        let known_seed = 12345u64;
        let targets = generate_cascade_targets(known_seed, XorshiftVariant::Xorshift64, &[5, 10, 15]);

        let config = AnalysisConfig {
            mask_bits: None,
            cascade_targets: Some(targets),
        };

        let analyzer = XorshiftAnalyzer::with_variant(XorshiftVariant::Xorshift64);
        let result = analyzer.analyze(&[0u8; 32], &config, None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        let details = result.details.unwrap();
        assert!(details.contains(&format!("seed={}", known_seed)));
        assert!(details.contains("xorshift64"));
    }

    #[test]
    fn test_cascade_finds_known_xorshift128_seed() {
        let known_seed = 54321u64;
        let targets = generate_cascade_targets(known_seed, XorshiftVariant::Xorshift128, &[5, 10, 15]);

        let config = AnalysisConfig {
            mask_bits: None,
            cascade_targets: Some(targets),
        };

        let analyzer = XorshiftAnalyzer::with_variant(XorshiftVariant::Xorshift128);
        let result = analyzer.analyze(&[0u8; 32], &config, None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        let details = result.details.unwrap();
        assert!(details.contains(&format!("seed={}", known_seed)));
        assert!(details.contains("xorshift128"));
    }

    #[test]
    fn test_cascade_finds_known_xorshift128plus_seed() {
        let known_seed = 99999u64;
        let targets = generate_cascade_targets(known_seed, XorshiftVariant::Xorshift128Plus, &[5, 10, 15]);

        let config = AnalysisConfig {
            mask_bits: None,
            cascade_targets: Some(targets),
        };

        let analyzer = XorshiftAnalyzer::with_variant(XorshiftVariant::Xorshift128Plus);
        let result = analyzer.analyze(&[0u8; 32], &config, None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        let details = result.details.unwrap();
        assert!(details.contains(&format!("seed={}", known_seed)));
        assert!(details.contains("xorshift128+"));
    }

    #[test]
    fn test_cascade_finds_known_xoroshiro_seed() {
        let known_seed = 77777u64;
        let targets = generate_cascade_targets(known_seed, XorshiftVariant::Xoroshiro128StarStar, &[5, 10, 15]);

        let config = AnalysisConfig {
            mask_bits: None,
            cascade_targets: Some(targets),
        };

        let analyzer = XorshiftAnalyzer::with_variant(XorshiftVariant::Xoroshiro128StarStar);
        let result = analyzer.analyze(&[0u8; 32], &config, None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        let details = result.details.unwrap();
        assert!(details.contains(&format!("seed={}", known_seed)));
        assert!(details.contains("xoroshiro128**"));
    }

    #[test]
    fn test_cascade_finds_zero_seed() {
        let known_seed = 0u64;
        let targets = generate_cascade_targets(known_seed, XorshiftVariant::Xorshift64, &[5, 10]);

        let config = AnalysisConfig {
            mask_bits: None,
            cascade_targets: Some(targets),
        };

        let analyzer = XorshiftAnalyzer::with_variant(XorshiftVariant::Xorshift64);
        let result = analyzer.analyze(&[0u8; 32], &config, None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
    }

    #[test]
    fn test_check_mask() {
        let mut key = [0u8; 32];
        key[31] = 0x15;

        assert!(check_mask(&key, 5, 0x15));
        assert!(!check_mask(&key, 5, 0x16));
    }

    #[test]
    fn test_all_variants_search() {
        let known_seed = 0xDEADBEEF_u64;
        let xorshift128plus_targets = generate_cascade_targets(known_seed, XorshiftVariant::Xorshift128Plus, &[5, 10, 15]);

        let config = AnalysisConfig {
            mask_bits: None,
            cascade_targets: Some(xorshift128plus_targets),
        };

        let analyzer = XorshiftAnalyzer::new();
        let result = analyzer.analyze(&[0u8; 32], &config, None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        let details = result.details.unwrap();
        let has_variant = details.contains("xorshift64")
            || details.contains("xorshift128+")
            || details.contains("xorshift128")
            || details.contains("xoroshiro");
        assert!(has_variant, "Expected variant name in: {}", details);
    }
}
