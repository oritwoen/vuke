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
