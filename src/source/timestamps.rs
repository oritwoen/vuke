//! Timestamp source - generate keys from date range.

use anyhow::Result;
use chrono::NaiveDate;
use indicatif::ProgressBar;
use rayon::prelude::*;

use super::{ProcessStats, Source};
use crate::derive::KeyDeriver;
use crate::matcher::Matcher;
use crate::output::Output;
use crate::transform::{Input, Transform};

/// Generate keys from Unix timestamps in a date range
pub struct TimestampSource {
    start: u64,
    end: u64,
    microseconds: bool,
}

impl TimestampSource {
    pub fn from_dates(start_date: &str, end_date: &str, microseconds: bool) -> Result<Self> {
        let start = NaiveDate::parse_from_str(start_date, "%Y-%m-%d")?
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp() as u64;

        let end = NaiveDate::parse_from_str(end_date, "%Y-%m-%d")?
            .and_hms_opt(23, 59, 59)
            .unwrap()
            .and_utc()
            .timestamp() as u64;

        Ok(Self {
            start,
            end,
            microseconds,
        })
    }
}

impl Source for TimestampSource {
    fn process(
        &self,
        transforms: &[Box<dyn Transform>],
        matcher: Option<&Matcher>,
        output: &dyn Output,
    ) -> Result<ProcessStats> {
        let count = self.end - self.start + 1;
        let total = if self.microseconds { count * 1000 } else { count };

        let pb = ProgressBar::new(total);
        pb.set_style(crate::default_progress_style());

        let timestamps: Vec<u64> = (self.start..=self.end).collect();
        let deriver = KeyDeriver::new();
        let stats = std::sync::atomic::AtomicU64::new(0);
        let matches = std::sync::atomic::AtomicU64::new(0);

        timestamps.par_iter().for_each(|&ts| {
            // Process base timestamp
            process_timestamp(
                ts,
                transforms,
                &deriver,
                matcher,
                output,
                &stats,
                &matches,
            );

            // Process microseconds if enabled
            if self.microseconds {
                for ms in 0u64..1000 {
                    let ts_ms = ts * 1000 + ms;
                    process_timestamp(
                        ts_ms,
                        transforms,
                        &deriver,
                        matcher,
                        output,
                        &stats,
                        &matches,
                    );
                }
                pb.inc(1001);
            } else {
                pb.inc(1);
            }
        });

        pb.finish_and_clear();

        Ok(ProcessStats {
            inputs_processed: total,
            keys_generated: stats.load(std::sync::atomic::Ordering::Relaxed),
            matches_found: matches.load(std::sync::atomic::Ordering::Relaxed),
        })
    }
}

fn process_timestamp(
    ts: u64,
    transforms: &[Box<dyn Transform>],
    deriver: &KeyDeriver,
    matcher: Option<&Matcher>,
    output: &dyn Output,
    stats: &std::sync::atomic::AtomicU64,
    matches: &std::sync::atomic::AtomicU64,
) {
    let inputs = vec![Input::from_u64(ts)];
    let mut buffer = Vec::with_capacity(6);

    for transform in transforms {
        buffer.clear();
        transform.apply_batch(&inputs, &mut buffer);

        for (source, key) in &buffer {
            let derived = deriver.derive(key);

            if let Some(m) = matcher {
                if let Some(match_info) = m.check(&derived) {
                    output.hit(source, transform.name(), &derived, &match_info).ok();
                    matches.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            } else {
                output.key(source, transform.name(), &derived).ok();
            }

            stats.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}
