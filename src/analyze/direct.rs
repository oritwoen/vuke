use indicatif::ProgressBar;
use super::{Analyzer, AnalysisConfig, AnalysisResult, AnalysisStatus, calculate_bit_length};

pub struct DirectAnalyzer;

impl Analyzer for DirectAnalyzer {
    fn name(&self) -> &'static str {
        "direct"
    }

    fn analyze(&self, key: &[u8; 32], config: &AnalysisConfig, _progress: Option<&ProgressBar>) -> AnalysisResult {
        if config.mask_bits.is_some() {
            return AnalysisResult {
                analyzer: self.name(),
                status: AnalysisStatus::Unknown,
                details: Some("masked analysis not supported".to_string()),
            };
        }

        let mut observations = Vec::new();

        let leading_zeros = key.iter().take_while(|&&b| b == 0).count();
        let trailing_zeros = key.iter().rev().take_while(|&&b| b == 0).count();

        let bit_length = calculate_bit_length(key);

        if bit_length <= 64 {
            observations.push(format!("bit_length={}, fits in u64", bit_length));
        }

        if leading_zeros >= 24 {
            observations.push(format!("BE padding detected ({} leading zero bytes)", leading_zeros));
        }

        if trailing_zeros >= 24 {
            observations.push(format!("LE padding detected ({} trailing zero bytes)", trailing_zeros));
        }

        if is_ascii_string(key) {
            let s: String = key.iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as char)
                .collect();
            observations.push(format!("ASCII string: \"{}\"", s));
        }

        let status = if observations.is_empty() {
            AnalysisStatus::NotFound
        } else {
            AnalysisStatus::Possible
        };

        let details = if observations.is_empty() {
            Some("no direct patterns detected".to_string())
        } else {
            Some(observations.join(", "))
        };

        AnalysisResult {
            analyzer: self.name(),
            status,
            details,
        }
    }
}

fn is_ascii_string(key: &[u8; 32]) -> bool {
    let non_null: Vec<_> = key.iter().take_while(|&&b| b != 0).collect();
    // Max 31 bytes to ensure at least one null terminator remains for detection
    if non_null.is_empty() || non_null.len() > 31 {
        return false;
    }

    let rest_is_null = key[non_null.len()..].iter().all(|&b| b == 0);
    let all_printable = non_null.iter().all(|&&b| (0x20..=0x7e).contains(&b));

    rest_is_null && all_printable && non_null.len() >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_number() {
        let mut key = [0u8; 32];
        key[31] = 42;
        let result = DirectAnalyzer.analyze(&key, &AnalysisConfig::default(), None);
        assert_eq!(result.status, AnalysisStatus::Possible);
        assert!(result.details.unwrap().contains("bit_length"));
    }

    #[test]
    fn test_ascii_string() {
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(b"test");
        let result = DirectAnalyzer.analyze(&key, &AnalysisConfig::default(), None);
        assert_eq!(result.status, AnalysisStatus::Possible);
        assert!(result.details.unwrap().contains("ASCII"));
    }

    #[test]
    fn test_random_key() {
        let key: [u8; 32] = [
            0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
            0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
            0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
            0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
        ];
        let result = DirectAnalyzer.analyze(&key, &AnalysisConfig::default(), None);
        assert_eq!(result.status, AnalysisStatus::NotFound);
    }
}
