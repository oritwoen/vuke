//! Input sources for key generation.
//!
//! Sources provide input data that gets transformed into private keys.

mod files;
mod range;
mod stdin;
mod timestamps;
mod wordlist;

pub use files::FilesSource;
pub use range::RangeSource;
pub use stdin::StdinSource;
pub use timestamps::TimestampSource;
pub use wordlist::WordlistSource;

use crate::derive::KeyDeriver;
use crate::matcher::Matcher;
use crate::output::Output;
use crate::transform::Transform;
use anyhow::Result;

/// Source trait for generating input data
pub trait Source: Send + Sync {
    /// Process all inputs through transforms and output matches
    fn process(
        &self,
        transforms: &[Box<dyn Transform>],
        deriver: &KeyDeriver,
        matcher: Option<&Matcher>,
        output: &dyn Output,
    ) -> Result<ProcessStats>;
}

/// Statistics from processing
#[derive(Default, Debug)]
pub struct ProcessStats {
    pub inputs_processed: u64,
    pub keys_generated: u64,
    pub matches_found: u64,
}

/// Available source types
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum SourceType {
    Range,
    Wordlist,
    Timestamps,
    Stdin,
}

/// Captures output errors inside Rayon closures where `?` can't be used.
///
/// Check `is_poisoned()` before each output call to skip work after failure.
/// Call `into_result()` after the parallel section to propagate the first error.
pub(crate) struct OutputGuard {
    poisoned: std::sync::atomic::AtomicBool,
    first_error: std::sync::Mutex<Option<String>>,
}

impl OutputGuard {
    pub fn new() -> Self {
        Self {
            poisoned: std::sync::atomic::AtomicBool::new(false),
            first_error: std::sync::Mutex::new(None),
        }
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn check(&self, result: Result<()>) {
        if let Err(e) = result {
            self.poisoned
                .store(true, std::sync::atomic::Ordering::Relaxed);
            let mut first = self.first_error.lock().unwrap();
            if first.is_none() {
                *first = Some(e.to_string());
            }
        }
    }

    pub fn into_result(self) -> Result<()> {
        if self.poisoned.load(std::sync::atomic::Ordering::Relaxed) {
            let msg = self
                .first_error
                .into_inner()
                .unwrap()
                .unwrap_or_else(|| "unknown output error".to_string());
            anyhow::bail!("Output failed: {}", msg)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_guard_ok_stays_clean() {
        let guard = OutputGuard::new();
        guard.check(Ok(()));
        guard.check(Ok(()));
        assert!(!guard.is_poisoned());
        assert!(guard.into_result().is_ok());
    }

    #[test]
    fn output_guard_captures_first_error() {
        let guard = OutputGuard::new();
        guard.check(Ok(()));
        guard.check(Err(anyhow::anyhow!("disk full")));
        guard.check(Err(anyhow::anyhow!("second error")));
        assert!(guard.is_poisoned());
        let err = guard.into_result().unwrap_err();
        assert!(err.to_string().contains("disk full"));
    }
}
