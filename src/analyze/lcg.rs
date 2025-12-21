//! LCG analyzer - brute-force search for Linear Congruential Generator seeds.

use indicatif::ProgressBar;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;

use crate::lcg::{generate_key, LcgEndian, LcgVariant, ALL_VARIANTS};
use super::{Analyzer, AnalysisConfig, AnalysisResult, AnalysisStatus};

pub struct LcgAnalyzer {
    variant: Option<LcgVariant>,
    endian: LcgEndian,
}

impl LcgAnalyzer {
    pub fn new() -> Self {
        Self {
            variant: None,
            endian: LcgEndian::Big,
        }
    }

    pub fn with_variant(variant: LcgVariant) -> Self {
        Self {
            variant: Some(variant),
            endian: LcgEndian::Big,
        }
    }

    pub fn with_endian(mut self, endian: LcgEndian) -> Self {
        self.endian = endian;
        self
    }

    fn analyze_variant(
        &self,
        key: &[u8; 32],
        config: &AnalysisConfig,
        variant: &LcgVariant,
        progress: Option<&ProgressBar>,
    ) -> Option<AnalysisResult> {
        match config.mask_bits {
            Some(bits) => self.analyze_masked(key, variant, bits, progress),
            None => self.analyze_exact(key, variant, progress),
        }
    }

    fn analyze_exact(
        &self,
        key: &[u8; 32],
        variant: &LcgVariant,
        progress: Option<&ProgressBar>,
    ) -> Option<AnalysisResult> {
        let found_seed = AtomicU32::new(0);
        let found = AtomicBool::new(false);

        let max_seed = variant.max_seed().min(u32::MAX as u64) as u32;
        let total = max_seed as u64 + 1;

        if let Some(pb) = progress {
            pb.set_length(total);
            pb.set_message(format!("lcg:{} brute-force", variant.name));
        }

        let chunk_size = 1_000_000u32;
        let progress_interval = 100_000u32;
        let num_chunks = (max_seed / chunk_size) + 1;
        let chunks: Vec<u32> = (0..num_chunks).collect();

        let endian = self.endian;

        chunks.par_iter().for_each(|&chunk_idx| {
            if found.load(Ordering::Acquire) {
                return;
            }

            let start = chunk_idx.saturating_mul(chunk_size);
            let end = start.saturating_add(chunk_size - 1).min(max_seed);
            let mut last_progress = start;

            for seed in start..=end {
                if found.load(Ordering::Acquire) {
                    if let Some(pb) = progress {
                        pb.inc((seed - last_progress) as u64);
                    }
                    return;
                }

                let candidate = generate_key(seed, variant, endian);

                if candidate == *key {
                    found_seed.store(seed, Ordering::Release);
                    found.store(true, Ordering::Release);
                    if let Some(pb) = progress {
                        pb.inc((seed - last_progress) as u64);
                    }
                    return;
                }

                if let Some(pb) = progress {
                    if seed - last_progress >= progress_interval {
                        pb.inc((seed - last_progress) as u64);
                        last_progress = seed;
                    }
                }
            }

            if let Some(pb) = progress {
                pb.inc((end - last_progress + 1) as u64);
            }
        });

        if let Some(pb) = progress {
            pb.finish_and_clear();
        }

        if found.load(Ordering::Acquire) {
            let seed = found_seed.load(Ordering::Acquire);
            Some(AnalysisResult {
                analyzer: "lcg",
                status: AnalysisStatus::Confirmed,
                details: Some(format!(
                    "variant={}, seed={}, endian={}",
                    variant.name, seed, self.endian.as_str()
                )),
            })
        } else {
            None
        }
    }

    fn analyze_masked(
        &self,
        target: &[u8; 32],
        variant: &LcgVariant,
        mask_bits: u8,
        progress: Option<&ProgressBar>,
    ) -> Option<AnalysisResult> {
        let target_u64 = u64::from_be_bytes(target[24..32].try_into().unwrap());

        let mask: u64 = if mask_bits >= 64 { u64::MAX } else { (1u64 << mask_bits) - 1 };
        let high_bit: u64 = 1u64 << (mask_bits - 1);

        let found_seed = AtomicU32::new(0);
        let found = AtomicBool::new(false);
        let found_full_key = Mutex::new([0u8; 32]);

        let max_seed = variant.max_seed().min(u32::MAX as u64) as u32;
        let total = max_seed as u64 + 1;

        if let Some(pb) = progress {
            pb.set_length(total);
            pb.set_message(format!("lcg:{} masked brute-force", variant.name));
        }

        let chunk_size = 1_000_000u32;
        let progress_interval = 100_000u32;
        let num_chunks = (max_seed / chunk_size) + 1;
        let chunks: Vec<u32> = (0..num_chunks).collect();

        let endian = self.endian;

        chunks.par_iter().for_each(|&chunk_idx| {
            if found.load(Ordering::Acquire) {
                return;
            }

            let start = chunk_idx.saturating_mul(chunk_size);
            let end = start.saturating_add(chunk_size - 1).min(max_seed);
            let mut last_progress = start;

            for seed in start..=end {
                if found.load(Ordering::Acquire) {
                    if let Some(pb) = progress {
                        pb.inc((seed - last_progress) as u64);
                    }
                    return;
                }

                let candidate = generate_key(seed, variant, endian);
                let full_key_u64 = u64::from_be_bytes(candidate[24..32].try_into().unwrap());
                let masked = (full_key_u64 & mask) | high_bit;

                if masked == target_u64 {
                    found_seed.store(seed, Ordering::Release);
                    found.store(true, Ordering::Release);
                    if let Ok(mut fk) = found_full_key.lock() {
                        *fk = candidate;
                    }
                    if let Some(pb) = progress {
                        pb.inc((seed - last_progress) as u64);
                    }
                    return;
                }

                if let Some(pb) = progress {
                    if seed - last_progress >= progress_interval {
                        pb.inc((seed - last_progress) as u64);
                        last_progress = seed;
                    }
                }
            }

            if let Some(pb) = progress {
                pb.inc((end - last_progress + 1) as u64);
            }
        });

        if let Some(pb) = progress {
            pb.finish_and_clear();
        }

        if found.load(Ordering::Acquire) {
            let seed = found_seed.load(Ordering::Acquire);
            let full_key = *found_full_key.lock().unwrap();
            let full_key_hex = hex::encode(full_key);
            let full_key_u64 = u64::from_be_bytes(full_key[24..32].try_into().unwrap());
            let masked_value = (full_key_u64 & mask) | high_bit;

            Some(AnalysisResult {
                analyzer: "lcg",
                status: AnalysisStatus::Confirmed,
                details: Some(format!(
                    "variant={}, seed={}, full_key={}, masked=0x{:x}, mask_bits={}, endian={}, formula=(key & 0x{:x}) | 0x{:x}",
                    variant.name, seed, full_key_hex, masked_value, mask_bits, self.endian.as_str(), mask, high_bit
                )),
            })
        } else {
            None
        }
    }
}

impl Default for LcgAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for LcgAnalyzer {
    fn name(&self) -> &'static str {
        "lcg"
    }

    fn supports_mask(&self) -> bool {
        true
    }

    fn is_brute_force(&self) -> bool {
        true
    }

    fn analyze(
        &self,
        key: &[u8; 32],
        config: &AnalysisConfig,
        progress: Option<&ProgressBar>,
    ) -> AnalysisResult {
        let variants: Vec<&LcgVariant> = match &self.variant {
            Some(v) => vec![v],
            None => ALL_VARIANTS.iter().collect(),
        };

        let mut checked_seeds: u64 = 0;
        let mut checked_variants = Vec::new();

        for variant in &variants {
            if let Some(result) = self.analyze_variant(key, config, variant, progress) {
                return result;
            }
            checked_seeds += variant.max_seed().min(u32::MAX as u64) + 1;
            checked_variants.push(variant.name);
        }

        AnalysisResult {
            analyzer: self.name(),
            status: AnalysisStatus::NotFound,
            details: Some(format!(
                "checked {} seeds across variants: {}",
                checked_seeds,
                checked_variants.join(", ")
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lcg::{GLIBC, MINSTD, MSVC};

    #[test]
    fn test_find_known_glibc_seed() {
        let seed = 42u32;
        let key = generate_key(seed, &GLIBC, LcgEndian::Big);

        let analyzer = LcgAnalyzer::with_variant(GLIBC);
        let result = analyzer.analyze(&key, &AnalysisConfig::default(), None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.as_ref().unwrap().contains("seed=42"));
        assert!(result.details.as_ref().unwrap().contains("variant=glibc"));
    }

    #[test]
    fn test_find_known_minstd_seed() {
        let seed = 12345u32;
        let key = generate_key(seed, &MINSTD, LcgEndian::Big);

        let analyzer = LcgAnalyzer::with_variant(MINSTD);
        let result = analyzer.analyze(&key, &AnalysisConfig::default(), None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.as_ref().unwrap().contains("seed=12345"));
    }

    #[test]
    fn test_find_seed_zero() {
        let key = generate_key(0, &GLIBC, LcgEndian::Big);

        let analyzer = LcgAnalyzer::with_variant(GLIBC);
        let result = analyzer.analyze(&key, &AnalysisConfig::default(), None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.as_ref().unwrap().contains("seed=0"));
    }

    #[test]
    fn test_find_with_little_endian() {
        let seed = 100u32;
        let key = generate_key(seed, &GLIBC, LcgEndian::Little);

        let analyzer = LcgAnalyzer::with_variant(GLIBC).with_endian(LcgEndian::Little);
        let result = analyzer.analyze(&key, &AnalysisConfig::default(), None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.as_ref().unwrap().contains("endian=le"));
    }

    #[test]
    #[ignore]
    fn test_not_found_wrong_endian() {
        let key = generate_key(42, &GLIBC, LcgEndian::Little);

        let analyzer = LcgAnalyzer::with_variant(GLIBC).with_endian(LcgEndian::Big);
        let result = analyzer.analyze(&key, &AnalysisConfig::default(), None);

        assert_eq!(result.status, AnalysisStatus::NotFound);
    }

    #[test]
    #[ignore]
    fn test_all_variants_finds_correct_one() {
        let seed = 999u32;
        let key = generate_key(seed, &MSVC, LcgEndian::Big);

        let analyzer = LcgAnalyzer::new();
        let result = analyzer.analyze(&key, &AnalysisConfig::default(), None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.as_ref().unwrap().contains("variant=msvc"));
    }

    #[test]
    fn test_masked_analysis() {
        let seed = 42u32;
        let full_key = generate_key(seed, &GLIBC, LcgEndian::Big);

        let mask_bits: u8 = 10;
        let mask: u64 = (1u64 << mask_bits) - 1;
        let high_bit: u64 = 1u64 << (mask_bits - 1);

        let full_key_u64 = u64::from_be_bytes(full_key[24..32].try_into().unwrap());
        let masked_value = (full_key_u64 & mask) | high_bit;

        let mut target = [0u8; 32];
        target[24..32].copy_from_slice(&masked_value.to_be_bytes());

        let config = AnalysisConfig { mask_bits: Some(mask_bits) };
        let analyzer = LcgAnalyzer::with_variant(GLIBC);
        let result = analyzer.analyze(&target, &config, None);

        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.as_ref().unwrap().contains("seed=42"));
        assert!(result.details.as_ref().unwrap().contains("mask_bits=10"));
    }
}
