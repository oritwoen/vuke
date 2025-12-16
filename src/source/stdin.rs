//! Stdin source - stream passphrases from stdin.

use anyhow::Result;
use std::io::{self, BufRead};

use super::{ProcessStats, Source};
use crate::derive::KeyDeriver;
use crate::matcher::Matcher;
use crate::output::Output;
use crate::transform::{Input, Transform};

/// Generate keys from stdin (streaming)
pub struct StdinSource;

impl StdinSource {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StdinSource {
    fn default() -> Self {
        Self::new()
    }
}

impl Source for StdinSource {
    fn process(
        &self,
        transforms: &[Box<dyn Transform>],
        matcher: Option<&Matcher>,
        output: &dyn Output,
    ) -> Result<ProcessStats> {
        let deriver = KeyDeriver::new();
        let stdin = io::stdin();
        let reader = stdin.lock();

        let mut inputs_processed = 0u64;
        let mut keys_generated = 0u64;
        let mut matches_found = 0u64;

        let mut buffer = Vec::with_capacity(16);
        let mut batch = Vec::with_capacity(1000);

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            batch.push(Input::from_string(trimmed.to_string()));
            inputs_processed += 1;

            // Process in batches
            if batch.len() >= 1000 {
                let (keys, found) = process_batch(&batch, transforms, &deriver, matcher, output, &mut buffer);
                keys_generated += keys;
                matches_found += found;
                batch.clear();
            }
        }

        // Process remaining
        if !batch.is_empty() {
            let (keys, found) = process_batch(&batch, transforms, &deriver, matcher, output, &mut buffer);
            keys_generated += keys;
            matches_found += found;
        }

        Ok(ProcessStats {
            inputs_processed,
            keys_generated,
            matches_found,
        })
    }
}

fn process_batch(
    inputs: &[Input],
    transforms: &[Box<dyn Transform>],
    deriver: &KeyDeriver,
    matcher: Option<&Matcher>,
    output: &dyn Output,
    buffer: &mut Vec<(String, [u8; 32])>,
) -> (u64, u64) {
    let mut keys_generated = 0u64;
    let mut matches_found = 0u64;

    for transform in transforms {
        buffer.clear();
        transform.apply_batch(inputs, buffer);

        for (source, key) in buffer.iter() {
            let derived = deriver.derive(key);

            if let Some(m) = matcher {
                if let Some(match_info) = m.check(&derived) {
                    output.hit(source, transform.name(), &derived, &match_info).ok();
                    matches_found += 1;
                }
            } else {
                output.key(source, transform.name(), &derived).ok();
            }

            keys_generated += 1;
        }
    }

    (keys_generated, matches_found)
}
