//! Key origin analysis - reverse detection of vulnerable generation methods.
//!
//! Analyzes private keys to determine if they could have been generated
//! by known vulnerable methods (Milksad, weak seeds, etc.).

mod key_parser;
mod milksad;
mod direct;
mod heuristic;
mod output;

pub use key_parser::{parse_private_key, ParseError};
pub use milksad::MilksadAnalyzer;
pub use direct::DirectAnalyzer;
pub use heuristic::HeuristicAnalyzer;
pub use output::{format_results, format_results_json};

use indicatif::ProgressBar;

pub fn calculate_bit_length(key: &[u8; 32]) -> u16 {
    match key.iter().position(|&b| b != 0) {
        Some(idx) => 256 - (idx as u16) * 8 - key[idx].leading_zeros() as u16,
        None => 0,
    }
}

/// Result of analyzing a key with a specific analyzer.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Name of the analyzer that produced this result
    pub analyzer: &'static str,
    /// Status of the analysis
    pub status: AnalysisStatus,
    /// Human-readable details
    pub details: Option<String>,
}

/// Status of key origin analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisStatus {
    /// Confirmed: found exact input that produces this key
    Confirmed,
    /// Possible: heuristics suggest this method could have been used
    Possible,
    /// NotFound: checked exhaustively, no match found
    NotFound,
    /// Unknown: cannot determine (e.g., hash functions are not reversible)
    Unknown,
}

impl AnalysisStatus {
    /// Symbol for terminal output
    pub fn symbol(&self) -> &'static str {
        match self {
            AnalysisStatus::Confirmed => "✓",
            AnalysisStatus::Possible => "?",
            AnalysisStatus::NotFound => "✗",
            AnalysisStatus::Unknown => "?",
        }
    }

    /// Status name for JSON output
    pub fn as_str(&self) -> &'static str {
        match self {
            AnalysisStatus::Confirmed => "confirmed",
            AnalysisStatus::Possible => "possible",
            AnalysisStatus::NotFound => "not_found",
            AnalysisStatus::Unknown => "unknown",
        }
    }
}

/// Trait for key origin analyzers.
pub trait Analyzer: Send + Sync {
    /// Human-readable name of this analyzer
    fn name(&self) -> &'static str;

    /// Analyze a key and return the result.
    /// 
    /// Progress bar is optional - used for long-running analyses like Milksad brute-force.
    fn analyze(&self, key: &[u8; 32], progress: Option<&ProgressBar>) -> AnalysisResult;

    /// Whether this analyzer requires brute-force (slow)
    fn is_brute_force(&self) -> bool {
        false
    }
}

/// Available analyzer types for CLI selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum AnalyzerType {
    Milksad,
    Direct,
    Heuristic,
}

impl AnalyzerType {
    /// Create analyzer instance
    pub fn create(self) -> Box<dyn Analyzer> {
        match self {
            AnalyzerType::Milksad => Box::new(MilksadAnalyzer),
            AnalyzerType::Direct => Box::new(DirectAnalyzer),
            AnalyzerType::Heuristic => Box::new(HeuristicAnalyzer),
        }
    }

    /// All available analyzer types
    pub fn all() -> Vec<AnalyzerType> {
        vec![
            AnalyzerType::Milksad,
            AnalyzerType::Direct,
            AnalyzerType::Heuristic,
        ]
    }

    /// Fast analyzers only (no brute-force)
    pub fn fast() -> Vec<AnalyzerType> {
        vec![
            AnalyzerType::Direct,
            AnalyzerType::Heuristic,
        ]
    }
}

/// Key metadata for analysis output.
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub hex: String,
    pub bit_length: u16,
    pub hamming_weight: u16,
    pub leading_zeros: u8,
}

impl KeyMetadata {
    pub fn from_key(key: &[u8; 32]) -> Self {
        let hex = hex::encode(key);
        let bit_length = calculate_bit_length(key);

        let hamming_weight: u16 = key.iter().map(|b| b.count_ones() as u16).sum();

        let leading_zeros = hex.chars().take_while(|&c| c == '0').count() as u8;

        Self {
            hex,
            bit_length,
            hamming_weight,
            leading_zeros,
        }
    }
}
