use indicatif::ProgressBar;
use rand_mt::Mt;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::{Analyzer, AnalysisConfig, AnalysisResult, AnalysisStatus};

pub struct MilksadAnalyzer;

impl Analyzer for MilksadAnalyzer {
    fn name(&self) -> &'static str {
        "milksad"
    }

    fn supports_mask(&self) -> bool {
        true
    }

    fn analyze(&self, key: &[u8; 32], config: &AnalysisConfig, progress: Option<&ProgressBar>) -> AnalysisResult {
        match config.mask_bits {
            Some(bits) => self.analyze_masked(key, bits, progress),
            None => self.analyze_exact(key, progress),
        }
    }

    fn is_brute_force(&self) -> bool {
        true
    }
}

impl MilksadAnalyzer {
    fn analyze_exact(&self, key: &[u8; 32], progress: Option<&ProgressBar>) -> AnalysisResult {
        let found_seed = AtomicU32::new(0);
        let found = AtomicBool::new(false);

        let total = u32::MAX as u64 + 1;
        if let Some(pb) = progress {
            pb.set_length(total);
            pb.set_message("milksad brute-force");
        }

        let chunk_size = 1_000_000u32;
        let progress_interval = 100_000u32;
        let chunks: Vec<u32> = (0..=(u32::MAX / chunk_size)).collect();

        chunks.par_iter().for_each(|&chunk_idx| {
            if found.load(Ordering::Acquire) {
                return;
            }

            let start = chunk_idx.saturating_mul(chunk_size);
            let end = start.saturating_add(chunk_size - 1);
            let mut last_progress = start;

            for seed in start..=end {
                if found.load(Ordering::Acquire) {
                    if let Some(pb) = progress {
                        pb.inc((seed - last_progress) as u64);
                    }
                    return;
                }

                let mut rng = Mt::new(seed);
                let mut candidate = [0u8; 32];
                rng.fill_bytes(&mut candidate);

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
            AnalysisResult {
                analyzer: self.name(),
                status: AnalysisStatus::Confirmed,
                details: Some(format!("seed = {}", seed)),
            }
        } else {
            AnalysisResult {
                analyzer: self.name(),
                status: AnalysisStatus::NotFound,
                details: Some(format!("checked {} seeds", total)),
            }
        }
    }

    fn analyze_masked(&self, target: &[u8; 32], mask_bits: u8, progress: Option<&ProgressBar>) -> AnalysisResult {
        let target_u64 = u64::from_be_bytes(target[24..32].try_into().unwrap());
        
        let mask: u64 = if mask_bits >= 64 { u64::MAX } else { (1u64 << mask_bits) - 1 };
        let high_bit: u64 = 1u64 << (mask_bits - 1);

        let found_seed = AtomicU32::new(0);
        let found = AtomicBool::new(false);

        let total = u32::MAX as u64 + 1;
        if let Some(pb) = progress {
            pb.set_length(total);
            pb.set_message("milksad masked brute-force");
        }

        let chunk_size = 1_000_000u32;
        let progress_interval = 100_000u32;
        let chunks: Vec<u32> = (0..=(u32::MAX / chunk_size)).collect();

        let found_full_key = std::sync::Mutex::new([0u8; 32]);

        chunks.par_iter().for_each(|&chunk_idx| {
            if found.load(Ordering::Acquire) {
                return;
            }

            let start = chunk_idx.saturating_mul(chunk_size);
            let end = start.saturating_add(chunk_size - 1);
            let mut last_progress = start;

            for seed in start..=end {
                if found.load(Ordering::Acquire) {
                    if let Some(pb) = progress {
                        pb.inc((seed - last_progress) as u64);
                    }
                    return;
                }

                let mut rng = Mt::new(seed);
                let mut candidate = [0u8; 32];
                rng.fill_bytes(&mut candidate);

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

            AnalysisResult {
                analyzer: self.name(),
                status: AnalysisStatus::Confirmed,
                details: Some(format!(
                    "seed = {}, full_key={}, masked=0x{:x}, mask_bits={}, formula=(key & 0x{:x}) | 0x{:x}",
                    seed, full_key_hex, masked_value, mask_bits, mask, high_bit
                )),
            }
        } else {
            AnalysisResult {
                analyzer: self.name(),
                status: AnalysisStatus::NotFound,
                details: Some(format!("checked {} seeds with {}-bit mask", total, mask_bits)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_find_known_seed() {
        let seed = 12345u32;
        let mut rng = Mt::new(seed);
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);

        let result = MilksadAnalyzer.analyze(&key, &AnalysisConfig::default(), None);
        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.unwrap().contains("12345"));
    }

    #[test]
    #[ignore]
    fn test_seed_zero() {
        let seed = 0u32;
        let mut rng = Mt::new(seed);
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);

        let result = MilksadAnalyzer.analyze(&key, &AnalysisConfig::default(), None);
        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.unwrap().contains("seed = 0"));
    }

    #[test]
    #[ignore]
    fn test_seed_last_chunk() {
        let seed = u32::MAX - 500_000;
        let mut rng = Mt::new(seed);
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);

        let result = MilksadAnalyzer.analyze(&key, &AnalysisConfig::default(), None);
        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.unwrap().contains(&format!("seed = {}", seed)));
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

    #[test]
    fn test_masked_key_extraction() {
        let seed = 42u32;
        let mut rng = Mt::new(seed);
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);

        let full_key_u64 = u64::from_be_bytes(key[24..32].try_into().unwrap());
        let mask_bits: u8 = 10;
        let mask: u64 = (1u64 << mask_bits) - 1;
        let high_bit: u64 = 1u64 << (mask_bits - 1);
        let masked = (full_key_u64 & mask) | high_bit;

        assert!(masked >= high_bit);
        assert!(masked < (1u64 << mask_bits));
    }
}
