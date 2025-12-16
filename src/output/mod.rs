//! Output handlers for generated keys.

mod console;

pub use console::ConsoleOutput;

use anyhow::Result;
use crate::derive::DerivedKey;
use crate::matcher::MatchInfo;

/// Output trait for handling generated keys.
pub trait Output: Send + Sync {
    /// Output a key (no matcher, output all keys).
    fn key(&self, source: &str, transform: &str, derived: &DerivedKey) -> Result<()>;

    /// Output a match hit (matcher found target).
    fn hit(&self, source: &str, transform: &str, derived: &DerivedKey, match_info: &MatchInfo) -> Result<()>;

    /// Flush any buffered output.
    fn flush(&self) -> Result<()>;
}
