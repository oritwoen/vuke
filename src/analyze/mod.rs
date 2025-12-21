//! Key origin analysis - reverse detection of vulnerable generation methods.
//!
//! Analyzes private keys to determine if they could have been generated
//! by known vulnerable methods (Milksad, weak seeds, etc.).

mod key_parser;
mod milksad;
mod direct;
mod heuristic;
mod lcg;
mod output;

pub use key_parser::{parse_private_key, parse_cascade, ParseError};
pub use milksad::MilksadAnalyzer;
pub use direct::DirectAnalyzer;
pub use heuristic::HeuristicAnalyzer;
pub use lcg::LcgAnalyzer;
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

#[derive(Debug, Clone, Default)]
pub struct AnalysisConfig {
    /// Formula: (full_key & (2^N - 1)) | 2^(N-1)
    pub mask_bits: Option<u8>,
    pub cascade_targets: Option<Vec<(u8, u64)>>,
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
    fn analyze(&self, key: &[u8; 32], config: &AnalysisConfig, progress: Option<&ProgressBar>) -> AnalysisResult;

    /// Whether this analyzer supports masked key analysis
    fn supports_mask(&self) -> bool {
        false
    }

    /// Whether this analyzer requires brute-force (slow)
    fn is_brute_force(&self) -> bool {
        false
    }
}

/// Available analyzer types for CLI selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnalyzerType {
    Milksad,
    Direct,
    Heuristic,
    Lcg {
        variant: Option<String>,
        endian: crate::lcg::LcgEndian,
    },
}

impl AnalyzerType {
    /// Create analyzer instance
    pub fn create(&self) -> Box<dyn Analyzer> {
        match self {
            AnalyzerType::Milksad => Box::new(MilksadAnalyzer),
            AnalyzerType::Direct => Box::new(DirectAnalyzer),
            AnalyzerType::Heuristic => Box::new(HeuristicAnalyzer),
            AnalyzerType::Lcg { variant, endian } => {
                let mut analyzer = match variant {
                    Some(name) => {
                        let v = crate::lcg::LcgVariant::from_str(name)
                            .expect("Invalid LCG variant");
                        LcgAnalyzer::with_variant(v)
                    }
                    None => LcgAnalyzer::new(),
                };
                analyzer = analyzer.with_endian(*endian);
                Box::new(analyzer)
            }
        }
    }

    /// All available analyzer types (default configurations)
    pub fn all() -> Vec<AnalyzerType> {
        vec![
            AnalyzerType::Milksad,
            AnalyzerType::Lcg { variant: None, endian: crate::lcg::LcgEndian::Big },
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

    /// Parse analyzer type from string.
    /// 
    /// Formats:
    /// - "milksad", "direct", "heuristic" - simple analyzers
    /// - "lcg" - all LCG variants, big-endian
    /// - "lcg:glibc" - specific variant, big-endian
    /// - "lcg:glibc:le" - specific variant, little-endian
    /// - "lcg::le" - all variants, little-endian
    pub fn from_str(s: &str) -> Result<Self, String> {
        let s = s.to_lowercase();
        
        if s == "milksad" {
            return Ok(AnalyzerType::Milksad);
        }
        if s == "direct" {
            return Ok(AnalyzerType::Direct);
        }
        if s == "heuristic" {
            return Ok(AnalyzerType::Heuristic);
        }
        
        if s == "lcg" || s.starts_with("lcg:") {
            return Self::parse_lcg(&s);
        }
        
        Err(format!("Unknown analyzer: {}. Valid: milksad, direct, heuristic, lcg[:variant][:endian]", s))
    }

    fn parse_lcg(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        
        let (variant, endian) = match parts.as_slice() {
            ["lcg"] => (None, crate::lcg::LcgEndian::Big),
            ["lcg", ""] => (None, crate::lcg::LcgEndian::Big),
            ["lcg", v] => {
                if let Some(e) = crate::lcg::LcgEndian::from_str(v) {
                    (None, e)
                } else if crate::lcg::LcgVariant::from_str(v).is_some() {
                    (Some(v.to_string()), crate::lcg::LcgEndian::Big)
                } else {
                    return Err(format!("Invalid LCG variant or endian: {}. Valid variants: glibc, minstd, msvc, borland. Valid endian: be, le", v));
                }
            }
            ["lcg", "", e] => {
                let endian = crate::lcg::LcgEndian::from_str(e)
                    .ok_or_else(|| format!("Invalid endian: {}. Valid: be, le", e))?;
                (None, endian)
            }
            ["lcg", v, e] => {
                if crate::lcg::LcgVariant::from_str(v).is_none() {
                    return Err(format!("Invalid LCG variant: {}. Valid: glibc, minstd, msvc, borland", v));
                }
                let endian = crate::lcg::LcgEndian::from_str(e)
                    .ok_or_else(|| format!("Invalid endian: {}. Valid: be, le", e))?;
                (Some(v.to_string()), endian)
            }
            _ => return Err("Invalid LCG format. Use: lcg, lcg:variant, lcg:variant:endian, lcg::endian".to_string()),
        };
        
        Ok(AnalyzerType::Lcg { variant, endian })
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
