//! Input sources for key generation.
//!
//! Sources provide input data that gets transformed into private keys.

mod range;
mod wordlist;
mod timestamps;
mod stdin;

pub use range::RangeSource;
pub use wordlist::WordlistSource;
pub use timestamps::TimestampSource;
pub use stdin::StdinSource;

use anyhow::Result;
use crate::transform::Transform;
use crate::matcher::Matcher;
use crate::output::Output;

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
