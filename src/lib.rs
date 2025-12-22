//! Vuke - Research tool for studying vulnerable Bitcoin key generation practices.
//!
//! This tool helps security researchers study historical vulnerabilities in Bitcoin
//! key generation, including weak PRNGs, predictable seeds, and insecure derivation methods.

pub mod analyze;
pub mod lcg;
pub mod source;
pub mod transform;
pub mod derive;
pub mod matcher;
pub mod output;
pub mod benchmark;
pub mod network;

pub use transform::Key;

/// Default progress bar style for CLI operations.
pub fn default_progress_style() -> indicatif::ProgressStyle {
    indicatif::ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec})")
        .unwrap()
        .progress_chars("#>-")
}
