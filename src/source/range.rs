//! Range source - generate keys from numeric range.

use anyhow::Result;
use indicatif::ProgressBar;
use rayon::prelude::*;

use super::{ProcessStats, Source};
use crate::derive::KeyDeriver;
use crate::matcher::Matcher;
use crate::output::Output;
use crate::transform::{Input, Transform};

/// Generate keys from a numeric range
pub struct RangeSource {
    pub start: u64,
    pub end: u64,
}

impl RangeSource {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }
}

impl Source for RangeSource {
    fn process(
        &self,
        transforms: &[Box<dyn Transform>],
        matcher: Option<&Matcher>,
        output: &dyn Output,
    ) -> Result<ProcessStats> {
        let count = self.end - self.start + 1;
        let pb = ProgressBar::new(count);
        pb.set_style(crate::default_progress_style());

        let range: Vec<u64> = (self.start..=self.end).collect();
        let deriver = KeyDeriver::new();

        let stats = std::sync::atomic::AtomicU64::new(0);
        let matches = std::sync::atomic::AtomicU64::new(0);

        range.par_chunks(1000).for_each(|chunk| {
            let inputs: Vec<Input> = chunk.iter().map(|&v| Input::from_u64(v)).collect();
            let mut buffer = Vec::with_capacity(inputs.len() * 3);

            for transform in transforms {
                buffer.clear();
                transform.apply_batch(&inputs, &mut buffer);

                for (source, key) in &buffer {
                    let derived = deriver.derive(key);

                    if let Some(m) = matcher {
                        if let Some(match_info) = m.check(&derived) {
                            output
                                .hit(source, transform.name(), &derived, &match_info)
                                .ok();
                            matches.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    } else {
                        // No matcher - output all keys
                        output.key(source, transform.name(), &derived).ok();
                    }

                    stats.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }

            pb.inc(chunk.len() as u64);
        });

        pb.finish_and_clear();

        Ok(ProcessStats {
            inputs_processed: count,
            keys_generated: stats.load(std::sync::atomic::Ordering::Relaxed),
            matches_found: matches.load(std::sync::atomic::Ordering::Relaxed),
        })
    }
}
