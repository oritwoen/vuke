//! Wordlist source - generate keys from file of passphrases.

use anyhow::Result;
use indicatif::ProgressBar;
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use super::{ProcessStats, Source};
use crate::derive::KeyDeriver;
use crate::matcher::Matcher;
use crate::output::Output;
use crate::transform::{Input, Transform};

/// Generate keys from a wordlist file
pub struct WordlistSource {
    lines: Vec<String>,
}

impl WordlistSource {
    pub fn from_file(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader
            .lines()
            .filter_map(Result::ok)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(Self { lines })
    }
}

impl Source for WordlistSource {
    fn process(
        &self,
        transforms: &[Box<dyn Transform>],
        matcher: Option<&Matcher>,
        output: &dyn Output,
    ) -> Result<ProcessStats> {
        let pb = ProgressBar::new(self.lines.len() as u64);
        pb.set_style(crate::default_progress_style());

        let deriver = KeyDeriver::new();
        let stats = std::sync::atomic::AtomicU64::new(0);
        let matches = std::sync::atomic::AtomicU64::new(0);

        self.lines.par_chunks(1000).for_each(|chunk| {
            let inputs: Vec<Input> = chunk.iter().map(|s| Input::from_string(s.clone())).collect();
            let mut buffer = Vec::with_capacity(inputs.len() * 2);

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

            pb.inc(chunk.len() as u64);
        });

        pb.finish_and_clear();

        Ok(ProcessStats {
            inputs_processed: self.lines.len() as u64,
            keys_generated: stats.load(std::sync::atomic::Ordering::Relaxed),
            matches_found: matches.load(std::sync::atomic::Ordering::Relaxed),
        })
    }
}
