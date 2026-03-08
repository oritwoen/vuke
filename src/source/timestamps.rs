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
            .timestamp();

        let end = NaiveDate::parse_from_str(end_date, "%Y-%m-%d")?
            .and_hms_opt(23, 59, 59)
            .unwrap()
            .and_utc()
            .timestamp();

        if start < 0 || end < 0 {
            anyhow::bail!("Dates before 1970-01-01 are not supported");
        }

        if end < start {
            anyhow::bail!(
                "Invalid date range: end ({}) must be on or after start ({})",
                end_date,
                start_date
            );
        }

        let start = u64::try_from(start)?;
        let end = u64::try_from(end)?;

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
        deriver: &KeyDeriver,
        matcher: Option<&Matcher>,
        output: &dyn Output,
    ) -> Result<ProcessStats> {
        if self.end < self.start {
            anyhow::bail!(
                "Invalid timestamp range: end ({}) must be greater than or equal to start ({})",
                self.end,
                self.start
            );
        }

        if self.microseconds && self.end > (u64::MAX - 999) / 1000 {
            anyhow::bail!(
                "Timestamp value overflow in microseconds mode for end timestamp {}",
                self.end
            );
        }

        let count = self
            .end
            .checked_sub(self.start)
            .and_then(|delta| delta.checked_add(1))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Timestamp range size overflow for {}..={}",
                    self.start,
                    self.end
                )
            })?;
        let total = if self.microseconds {
            count.checked_mul(1001).ok_or_else(|| {
                anyhow::anyhow!(
                    "Timestamp workload overflow in microseconds mode for {} inputs",
                    count
                )
            })?
        } else {
            count
        };

        let pb = ProgressBar::new(total);
        pb.set_style(crate::default_progress_style());

        let stats = std::sync::atomic::AtomicU64::new(0);
        let matches = std::sync::atomic::AtomicU64::new(0);

        (self.start..=self.end).into_par_iter().for_each(|ts| {
            // Process base timestamp
            process_timestamp(ts, transforms, &deriver, matcher, output, &stats, &matches);

            // Process microseconds if enabled
            if self.microseconds {
                for ms in 0u64..1000 {
                    let ts_ms = ts * 1000 + ms;
                    process_timestamp(
                        ts_ms, transforms, &deriver, matcher, output, &stats, &matches,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::KeyDeriver;
    use crate::output::ConsoleOutput;

    #[test]
    fn from_dates_rejects_descending_date_range() {
        let result = TimestampSource::from_dates("2025-01-02", "2025-01-01", false);
        assert!(result.is_err());
    }

    #[test]
    fn from_dates_rejects_pre_epoch_dates() {
        let result = TimestampSource::from_dates("1969-12-31", "1970-01-01", false);
        assert!(result.is_err());
    }

    #[test]
    fn process_counts_microseconds_mode_correctly() {
        let source = TimestampSource {
            start: 1,
            end: 1,
            microseconds: true,
        };
        let deriver = KeyDeriver::new();
        let output = ConsoleOutput::new();
        let transforms: Vec<Box<dyn Transform>> = Vec::new();

        let stats = source
            .process(&transforms, &deriver, None, &output)
            .expect("timestamp processing should succeed");

        assert_eq!(stats.inputs_processed, 1001);
    }

    #[test]
    fn process_rejects_descending_timestamp_range() {
        let source = TimestampSource {
            start: 10,
            end: 1,
            microseconds: false,
        };
        let deriver = KeyDeriver::new();
        let output = ConsoleOutput::new();
        let transforms: Vec<Box<dyn Transform>> = Vec::new();

        let result = source.process(&transforms, &deriver, None, &output);
        assert!(result.is_err());
    }

    #[test]
    fn process_rejects_overflowing_timestamp_range_size() {
        let source = TimestampSource {
            start: 0,
            end: u64::MAX,
            microseconds: false,
        };
        let deriver = KeyDeriver::new();
        let output = ConsoleOutput::new();
        let transforms: Vec<Box<dyn Transform>> = Vec::new();

        let result = source.process(&transforms, &deriver, None, &output);
        assert!(result.is_err());
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
}
