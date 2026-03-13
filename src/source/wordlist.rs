//! Wordlist source - generate keys from file of passphrases.
//!
//! Streams the file in chunks to avoid loading entire wordlists into memory.

use anyhow::Result;
use indicatif::ProgressBar;
use rayon::prelude::*;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use super::{ProcessStats, Source};
use crate::derive::KeyDeriver;
use crate::matcher::Matcher;
use crate::output::Output;
use crate::transform::{Input, Transform};

const CHUNK_SIZE: usize = 10_000;
const BATCH_SIZE: usize = 1000;

/// Generate keys from a wordlist file
pub struct WordlistSource {
    path: PathBuf,
}

impl WordlistSource {
    pub fn from_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            anyhow::bail!("Wordlist file not found: {}", path.display());
        }
        if !path.is_file() {
            anyhow::bail!("Not a file: {}", path.display());
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }
}

impl Source for WordlistSource {
    fn process(
        &self,
        transforms: &[Box<dyn Transform>],
        deriver: &KeyDeriver,
        matcher: Option<&Matcher>,
        output: &dyn Output,
    ) -> Result<ProcessStats> {
        let file_size = fs::metadata(&self.path)?.len();
        let pb = ProgressBar::new(file_size);
        pb.set_style(crate::default_progress_style());

        let stats = std::sync::atomic::AtomicU64::new(0);
        let matches = std::sync::atomic::AtomicU64::new(0);
        let mut inputs_processed = 0u64;
        let mut bytes_consumed = 0u64;

        let file = std::fs::File::open(&self.path)?;
        let mut reader = BufReader::new(file);
        let mut chunk = Vec::with_capacity(CHUNK_SIZE);
        let mut line_buf = String::new();

        loop {
            line_buf.clear();
            let bytes_read = match reader.read_line(&mut line_buf) {
                Ok(0) => break,
                Ok(n) => n as u64,
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    // Skip invalid UTF-8 lines; estimate 1 byte consumed to keep progress moving
                    bytes_consumed += 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            bytes_consumed += bytes_read;

            let trimmed = line_buf.trim().to_string();
            if trimmed.is_empty() {
                continue;
            }

            chunk.push(trimmed);
            inputs_processed += 1;

            if chunk.len() >= CHUNK_SIZE {
                process_chunk(
                    &chunk, transforms, deriver, matcher, output, &stats, &matches,
                );
                pb.set_position(bytes_consumed);
                chunk.clear();
            }
        }

        if !chunk.is_empty() {
            process_chunk(
                &chunk, transforms, deriver, matcher, output, &stats, &matches,
            );
        }

        pb.finish_and_clear();

        Ok(ProcessStats {
            inputs_processed,
            keys_generated: stats.load(std::sync::atomic::Ordering::Relaxed),
            matches_found: matches.load(std::sync::atomic::Ordering::Relaxed),
        })
    }
}

fn process_chunk(
    lines: &[String],
    transforms: &[Box<dyn Transform>],
    deriver: &KeyDeriver,
    matcher: Option<&Matcher>,
    output: &dyn Output,
    stats: &std::sync::atomic::AtomicU64,
    matches: &std::sync::atomic::AtomicU64,
) {
    lines.par_chunks(BATCH_SIZE).for_each(|batch| {
        let inputs: Vec<Input> = batch
            .iter()
            .map(|s| Input::from_string(s.clone()))
            .collect();
        let mut buffer = Vec::with_capacity(inputs.len() * 2);

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
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::KeyDeriver;
    use crate::output::ConsoleOutput;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn from_file_not_found() {
        let result = WordlistSource::from_file(Path::new("/nonexistent/path/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn from_file_not_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let result = WordlistSource::from_file(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn process_empty_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"").unwrap();

        let source = WordlistSource::from_file(file.path()).unwrap();
        let deriver = KeyDeriver::new();
        let output = ConsoleOutput::new();
        let transforms: Vec<Box<dyn Transform>> = Vec::new();

        let stats = source
            .process(&transforms, &deriver, None, &output)
            .unwrap();
        assert_eq!(stats.inputs_processed, 0);
    }

    #[test]
    fn process_skips_blank_lines() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"hello\n\n  \nworld\n").unwrap();

        let source = WordlistSource::from_file(file.path()).unwrap();
        let deriver = KeyDeriver::new();
        let output = ConsoleOutput::new();
        let transforms: Vec<Box<dyn Transform>> = Vec::new();

        let stats = source
            .process(&transforms, &deriver, None, &output)
            .unwrap();
        assert_eq!(stats.inputs_processed, 2);
    }

    #[test]
    fn process_skips_invalid_utf8() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"valid\n\xff\xfe\ninvalid bytes\ntest\n")
            .unwrap();

        let source = WordlistSource::from_file(file.path()).unwrap();
        let deriver = KeyDeriver::new();
        let output = ConsoleOutput::new();
        let transforms: Vec<Box<dyn Transform>> = Vec::new();

        let stats = source
            .process(&transforms, &deriver, None, &output)
            .unwrap();
        assert_eq!(stats.inputs_processed, 3);
    }
}
