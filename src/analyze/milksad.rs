use indicatif::ProgressBar;
use rand_mt::Mt;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::{Analyzer, AnalysisResult, AnalysisStatus};

pub struct MilksadAnalyzer;

impl Analyzer for MilksadAnalyzer {
    fn name(&self) -> &'static str {
        "milksad"
    }

    fn analyze(&self, key: &[u8; 32], progress: Option<&ProgressBar>) -> AnalysisResult {
        let found_seed = AtomicU32::new(0);
        let found = AtomicBool::new(false);

        let total = u32::MAX as u64 + 1;
        if let Some(pb) = progress {
            pb.set_length(total);
            pb.set_message("milksad brute-force");
        }

        let chunk_size = 1_000_000u32;
        let chunks: Vec<u32> = (0..=(u32::MAX / chunk_size)).collect();

        chunks.par_iter().for_each(|&chunk_idx| {
            if found.load(Ordering::Relaxed) {
                return;
            }

            let start = chunk_idx.saturating_mul(chunk_size);
            let end = start.saturating_add(chunk_size - 1).min(u32::MAX);

            for seed in start..=end {
                if found.load(Ordering::Relaxed) {
                    return;
                }

                let mut rng = Mt::new(seed);
                let mut candidate = [0u8; 32];
                rng.fill_bytes(&mut candidate);

                if candidate == *key {
                    found_seed.store(seed, Ordering::Relaxed);
                    found.store(true, Ordering::Relaxed);
                    return;
                }
            }

            if let Some(pb) = progress {
                pb.inc(chunk_size as u64);
            }
        });

        if let Some(pb) = progress {
            pb.finish_and_clear();
        }

        if found.load(Ordering::Relaxed) {
            let seed = found_seed.load(Ordering::Relaxed);
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

    fn is_brute_force(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_known_seed() {
        let seed = 12345u32;
        let mut rng = Mt::new(seed);
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);

        let result = MilksadAnalyzer.analyze(&key, None);
        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.unwrap().contains("12345"));
    }

    #[test]
    fn test_seed_zero() {
        let seed = 0u32;
        let mut rng = Mt::new(seed);
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);

        let result = MilksadAnalyzer.analyze(&key, None);
        assert_eq!(result.status, AnalysisStatus::Confirmed);
        assert!(result.details.unwrap().contains("seed = 0"));
    }
}
