//! Range source - generate keys from numeric range.

use anyhow::Result;
use indicatif::ProgressBar;
use rayon::prelude::*;

use super::{ProcessStats, Source};
use crate::derive::KeyDeriver;
use crate::matcher::Matcher;
use crate::output::Output;
use crate::transform::{Input, Transform};

const BATCH_SIZE: u64 = 1000;

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
        deriver: &KeyDeriver,
        matcher: Option<&Matcher>,
        output: &dyn Output,
    ) -> Result<ProcessStats> {
        if self.end < self.start {
            anyhow::bail!(
                "Invalid range: end ({}) must be greater than or equal to start ({})",
                self.end,
                self.start
            );
        }

        let count = self
            .end
            .checked_sub(self.start)
            .and_then(|delta| delta.checked_add(1))
            .ok_or_else(|| {
                anyhow::anyhow!("Range size overflow for {}..={}", self.start, self.end)
            })?;
        let pb = ProgressBar::new(count);
        pb.set_style(crate::default_progress_style());

        let stats = std::sync::atomic::AtomicU64::new(0);
        let matches = std::sync::atomic::AtomicU64::new(0);

        let num_batches = count / BATCH_SIZE + u64::from(count % BATCH_SIZE != 0);

        (0..num_batches).into_par_iter().for_each(|batch_idx| {
            let batch_start = self.start + batch_idx * BATCH_SIZE;
            let batch_end = batch_start.saturating_add(BATCH_SIZE - 1).min(self.end);

            let inputs: Vec<Input> = (batch_start..=batch_end).map(Input::from_u64).collect();
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
                        output.key(source, transform.name(), &derived).ok();
                    }

                    stats.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }

            pb.inc((batch_end - batch_start + 1) as u64);
        });

        pb.finish_and_clear();

        Ok(ProcessStats {
            inputs_processed: count,
            keys_generated: stats.load(std::sync::atomic::Ordering::Relaxed),
            matches_found: matches.load(std::sync::atomic::Ordering::Relaxed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::KeyDeriver;
    use crate::output::ConsoleOutput;

    #[test]
    fn process_rejects_descending_range() {
        let source = RangeSource::new(10, 1);
        let deriver = KeyDeriver::new();
        let output = ConsoleOutput::new();
        let transforms: Vec<Box<dyn Transform>> = Vec::new();

        let result = source.process(&transforms, &deriver, None, &output);
        assert!(result.is_err());
    }

    #[test]
    fn process_rejects_overflowing_range_size() {
        let source = RangeSource::new(0, u64::MAX);
        let deriver = KeyDeriver::new();
        let output = ConsoleOutput::new();
        let transforms: Vec<Box<dyn Transform>> = Vec::new();

        let result = source.process(&transforms, &deriver, None, &output);
        assert!(result.is_err());
    }
}
