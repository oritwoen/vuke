//! Vuke - Research tool for studying vulnerable Bitcoin key generation practices.
//!
//! This tool helps security researchers study historical vulnerabilities in Bitcoin
//! key generation, including weak PRNGs, predictable seeds, and insecure derivation methods.

pub mod analyze;
pub mod electrum;
pub mod lcg;
pub mod mt64;
pub mod multibit;
pub mod sha256_chain;
pub mod source;
pub mod transform;
pub mod xorshift;
pub mod derive;
pub mod matcher;
pub mod output;
pub mod benchmark;
pub mod network;
pub mod provider;

#[cfg(feature = "gpu")]
pub mod gpu;

#[cfg(feature = "storage")]
pub mod storage;

pub use transform::Key;

/// Default progress bar style for CLI operations.
pub fn default_progress_style() -> indicatif::ProgressStyle {
    indicatif::ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec})")
        .unwrap()
        .progress_chars("#>-")
}
