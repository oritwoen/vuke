use indicatif::ProgressBar;
use super::{Analyzer, AnalysisResult, AnalysisStatus};

pub struct HeuristicAnalyzer;

impl Analyzer for HeuristicAnalyzer {
    fn name(&self) -> &'static str {
        "heuristic"
    }

    fn analyze(&self, key: &[u8; 32], _progress: Option<&ProgressBar>) -> AnalysisResult {
        let entropy = calculate_byte_entropy(key);
        let hamming = key.iter().map(|b| b.count_ones()).sum::<u32>();

        let mut observations = Vec::new();

        if entropy < 4.0 {
            observations.push(format!("low entropy ({:.2})", entropy));
        }

        if hamming < 100 || hamming > 156 {
            observations.push(format!("unusual hamming weight ({})", hamming));
        }

        if has_repeating_pattern(key) {
            observations.push("repeating byte pattern".to_string());
        }

        let status = if observations.is_empty() {
            AnalysisStatus::Unknown
        } else {
            AnalysisStatus::Possible
        };

        let details = if observations.is_empty() {
            Some(format!("entropy={:.2}, hamming={}", entropy, hamming))
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

fn calculate_byte_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn has_repeating_pattern(key: &[u8; 32]) -> bool {
    for pattern_len in 1..=8 {
        if 32 % pattern_len == 0 {
            let pattern = &key[..pattern_len];
            let is_repeating = key.chunks(pattern_len).all(|chunk| chunk == pattern);
            if is_repeating && !pattern.iter().all(|&b| b == pattern[0]) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_entropy_key() {
        let key: [u8; 32] = [
            0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
            0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
            0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
            0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
        ];
        let result = HeuristicAnalyzer.analyze(&key, None);
        assert_eq!(result.status, AnalysisStatus::Unknown);
    }

    #[test]
    fn test_low_entropy_key() {
        let key = [0u8; 32];
        let result = HeuristicAnalyzer.analyze(&key, None);
        assert_eq!(result.status, AnalysisStatus::Possible);
    }

    #[test]
    fn test_repeating_pattern() {
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = (i % 4) as u8 + 1;
        }
        let result = HeuristicAnalyzer.analyze(&key, None);
        assert_eq!(result.status, AnalysisStatus::Possible);
    }
}
