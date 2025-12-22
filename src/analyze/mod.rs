//! Key origin analysis - reverse detection of vulnerable generation methods.
//!
//! Analyzes private keys to determine if they could have been generated
//! by known vulnerable methods (Milksad, weak seeds, etc.).

mod key_parser;
mod milksad;
mod mt64;
mod multibit;
mod direct;
mod heuristic;
mod lcg;
mod xorshift;
mod output;

pub use key_parser::{parse_private_key, parse_cascade, ParseError};
pub use milksad::MilksadAnalyzer;
pub use mt64::Mt64Analyzer;
pub use multibit::MultibitAnalyzer;
pub use direct::DirectAnalyzer;
pub use heuristic::HeuristicAnalyzer;
pub use lcg::LcgAnalyzer;
pub use xorshift::XorshiftAnalyzer;
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
    Mt64,
    MultibitHd {
        mnemonic: Option<String>,
        mnemonic_file: Option<std::path::PathBuf>,
        passphrase: String,
    },
    Direct,
    Heuristic,
    Lcg {
        variant: Option<crate::lcg::LcgVariant>,
        endian: crate::lcg::LcgEndian,
    },
    Xorshift {
        variant: Option<crate::xorshift::XorshiftVariant>,
    },
}

impl AnalyzerType {
    /// Create analyzer instance
    pub fn create(&self) -> Box<dyn Analyzer> {
        match self {
            AnalyzerType::Milksad => Box::new(MilksadAnalyzer),
            AnalyzerType::Mt64 => Box::new(Mt64Analyzer),
            AnalyzerType::MultibitHd { mnemonic, mnemonic_file, passphrase } => {
                let mut analyzer = MultibitAnalyzer::new().with_passphrase(passphrase.clone());
                if let Some(m) = mnemonic {
                    analyzer = analyzer.with_mnemonic(m.clone());
                }
                if let Some(f) = mnemonic_file {
                    analyzer = analyzer.with_mnemonic_file(f.clone());
                }
                Box::new(analyzer)
            }
            AnalyzerType::Direct => Box::new(DirectAnalyzer),
            AnalyzerType::Heuristic => Box::new(HeuristicAnalyzer),
            AnalyzerType::Lcg { variant, endian } => {
                let analyzer = match variant {
                    Some(v) => LcgAnalyzer::with_variant(*v),
                    None => LcgAnalyzer::new(),
                };
                Box::new(analyzer.with_endian(*endian))
            }
            AnalyzerType::Xorshift { variant } => {
                let analyzer = match variant {
                    Some(v) => XorshiftAnalyzer::with_variant(*v),
                    None => XorshiftAnalyzer::new(),
                };
                Box::new(analyzer)
            }
        }
    }

    /// All available analyzer types (default configurations)
    pub fn all() -> Vec<AnalyzerType> {
        vec![
            AnalyzerType::Milksad,
            AnalyzerType::Mt64,
            AnalyzerType::Lcg { variant: None, endian: crate::lcg::LcgEndian::Big },
            AnalyzerType::Xorshift { variant: None },
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

    pub fn from_str(s: &str) -> Result<Self, String> {
        let s = s.to_lowercase();
        
        match s.as_str() {
            "milksad" => Ok(AnalyzerType::Milksad),
            "mt64" => Ok(AnalyzerType::Mt64),
            "multibit-hd" | "multibit" => Ok(AnalyzerType::MultibitHd {
                mnemonic: None,
                mnemonic_file: None,
                passphrase: String::new(),
            }),
            "direct" => Ok(AnalyzerType::Direct),
            "heuristic" => Ok(AnalyzerType::Heuristic),
            _ if s == "lcg" || s.starts_with("lcg:") => {
                let config = crate::lcg::LcgConfig::parse(&s)?;
                Ok(AnalyzerType::Lcg { 
                    variant: config.variant, 
                    endian: config.endian,
                })
            }
            _ if s == "xorshift" || s.starts_with("xorshift:") => {
                let config = crate::xorshift::XorshiftConfig::parse(&s)?;
                Ok(AnalyzerType::Xorshift {
                    variant: config.variant,
                })
            }
            _ => Err(format!("Unknown analyzer: {}. Valid: milksad, mt64, multibit-hd, direct, heuristic, lcg[:variant][:endian], xorshift[:variant]", s)),
        }
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
