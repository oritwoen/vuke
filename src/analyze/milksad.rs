use indicatif::ProgressBar;
use rand_mt::Mt;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::{Analyzer, AnalysisConfig, AnalysisResult, AnalysisStatus};

#[derive(Debug, Clone)]
pub struct CascadeMatch {
    pub bits: u8,
    pub target: u64,
    pub full_key_hex: String,
}

#[derive(Debug, Clone)]
pub struct CascadeResult {
    pub seed: u32,
    pub matches: Vec<CascadeMatch>,
}

pub struct MilksadAnalyzer;

impl Analyzer for MilksadAnalyzer {
    fn name(&self) -> &'static str {
        "milksad"
    }

    fn supports_mask(&self) -> bool {
        true
    }

    fn analyze(&self, key: &[u8; 32], config: &AnalysisConfig, progress: Option<&ProgressBar>) -> AnalysisResult {
        if let Some(ref targets) = config.cascade_targets {
            return self.analyze_cascading(targets, progress);
        }

        match config.mask_bits {
            Some(bits) => self.analyze_masked(key, bits, progress),
            None => self.analyze_exact(key, progress),
        }
    }

    fn is_brute_force(&self) -> bool {
        true
    }

    #[cfg(feature = "gpu")]
    fn supports_gpu(&self) -> bool {
        true
    }

    #[cfg(feature = "gpu")]
    fn analyze_gpu(
        &self,
        ctx: &crate::gpu::GpuContext,
        key: &[u8; 32],
        config: &AnalysisConfig,
        progress: Option<&ProgressBar>,
    ) -> Result<AnalysisResult, crate::gpu::GpuError> {
        // GPU acceleration only for exact match (no mask, no cascade)
        if config.cascade_targets.is_some() || config.mask_bits.is_some() {
            return Ok(self.analyze(key, config, progress));
        }

        self.analyze_exact_gpu(ctx, key, progress)
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

    fn analyze_cascading(&self, targets: &[(u8, u64)], progress: Option<&ProgressBar>) -> AnalysisResult {
        let found_seed = AtomicU32::new(0);
        let found = AtomicBool::new(false);

        let total = u32::MAX as u64 + 1;
        if let Some(pb) = progress {
            pb.set_length(total);
            pb.set_message("milksad cascade brute-force");
        }

        let chunk_size = 1_000_000u32;
        let progress_interval = 100_000u32;
        let chunks: Vec<u32> = (0..=(u32::MAX / chunk_size)).collect();

        let found_keys: std::sync::Mutex<Vec<[u8; 32]>> = std::sync::Mutex::new(Vec::new());

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
                let mut keys: Vec<[u8; 32]> = Vec::with_capacity(targets.len());
                let mut all_matched = true;

                for (bits, target) in targets.iter() {
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

                    keys.push(key);
                }

                if all_matched {
                    found_seed.store(seed, Ordering::Release);
                    found.store(true, Ordering::Release);
                    if let Ok(mut fk) = found_keys.lock() {
                        *fk = keys;
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
            let keys = found_keys.lock().unwrap().clone();

            let matches: Vec<CascadeMatch> = targets
                .iter()
                .zip(keys.iter())
                .map(|((bits, target), key)| CascadeMatch {
                    bits: *bits,
                    target: *target,
                    full_key_hex: hex::encode(key),
                })
                .collect();

            let cascade_result = CascadeResult { seed, matches };
            let details = format_cascade_result(&cascade_result);

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
                    "checked {} seeds, cascade=[{}]",
                    total,
                    target_desc.join(",")
                )),
            }
        }
    }
}

fn format_cascade_result(result: &CascadeResult) -> String {
    let mut lines = vec![format!("seed={} (0x{:08x})", result.seed, result.seed)];

    for m in &result.matches {
        lines.push(format!(
            "  P{}: target=0x{:x}, full_key={}",
            m.bits, m.target, m.full_key_hex
        ));
    }

    lines.join("\n")
}

#[cfg(feature = "gpu")]
impl MilksadAnalyzer {
    /// GPU-accelerated exact match brute-force.
    fn analyze_exact_gpu(
        &self,
        ctx: &crate::gpu::GpuContext,
        key: &[u8; 32],
        progress: Option<&ProgressBar>,
    ) -> Result<AnalysisResult, crate::gpu::GpuError> {
        use crate::gpu::GpuMt19937Pipeline;

        let pipeline = GpuMt19937Pipeline::new(ctx)?;

        let total: u64 = u32::MAX as u64 + 1;
        if let Some(pb) = progress {
            pb.set_length(total);
            pb.set_message("milksad GPU brute-force");
        }

        // Batch size: 4M seeds per GPU dispatch (limited by max workgroups = 65535)
        // With workgroup_size=64: 4M / 64 = 62500 workgroups < 65535
        const BATCH_SIZE: u32 = 4_000_000;

        let result = pipeline.search_full(key, BATCH_SIZE, |seeds_tested, found_seed| {
            if let Some(pb) = progress {
                pb.set_position(seeds_tested);
            }

            // Return true to continue, false to stop
            found_seed.is_none()
        })?;

        if let Some(pb) = progress {
            pb.finish_and_clear();
        }

        if let Some(seed) = result.found_seed {
            Ok(AnalysisResult {
                analyzer: self.name(),
                status: AnalysisStatus::Confirmed,
                details: Some(format!("seed = {} (GPU)", seed)),
            })
        } else {
            Ok(AnalysisResult {
                analyzer: self.name(),
                status: AnalysisStatus::NotFound,
                details: Some(format!("checked {} seeds (GPU)", result.seeds_tested)),
            })
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

    fn apply_mask(key: &[u8; 32], bits: u8) -> u64 {
        let key_u64 = u64::from_be_bytes(key[24..32].try_into().unwrap());
        let mask: u64 = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        let high_bit: u64 = 1u64 << (bits - 1);
        (key_u64 & mask) | high_bit
    }

    fn generate_cascade_targets(seed: u32, bit_widths: &[u8]) -> Vec<(u8, u64)> {
        let mut rng = Mt::new(seed);
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
    fn test_cascade_sequential_rng() {
        let seed = 12345u32;
        let mut rng = Mt::new(seed);

        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        rng.fill_bytes(&mut key1);
        rng.fill_bytes(&mut key2);

        assert_ne!(key1, key2);

        let mut rng2 = Mt::new(seed);
        let mut key1_verify = [0u8; 32];
        let mut key2_verify = [0u8; 32];
        rng2.fill_bytes(&mut key1_verify);
        rng2.fill_bytes(&mut key2_verify);

        assert_eq!(key1, key1_verify);
        assert_eq!(key2, key2_verify);
    }

    #[test]
    fn test_generate_cascade_targets() {
        let seed = 42u32;
        let targets = generate_cascade_targets(seed, &[5, 10, 20]);

        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].0, 5);
        assert_eq!(targets[1].0, 10);
        assert_eq!(targets[2].0, 20);

        for (bits, target) in &targets {
            let high_bit = 1u64 << (bits - 1);
            assert!(target & high_bit != 0, "high bit must be set for P{}", bits);
            assert!(*target < (1u64 << bits), "target must fit in {} bits", bits);
        }
    }

    #[test]
    #[ignore]
    fn test_cascade_finds_known_seed() {
        let known_seed = 100u32;
        let targets = generate_cascade_targets(known_seed, &[5, 10, 15]);

        let config = AnalysisConfig {
            mask_bits: None,
            cascade_targets: Some(targets),
        };

        let result = MilksadAnalyzer.analyze(&[0u8; 32], &config, None);
        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.unwrap().contains(&format!("seed={}", known_seed)));
    }
}
