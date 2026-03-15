use std::fmt::Write;

use super::{AnalysisResult, KeyMetadata};

pub fn format_results(metadata: &KeyMetadata, results: &[AnalysisResult]) -> String {
    let mut output = String::new();

    let _ = writeln!(output, "Private Key: {}", metadata.hex);
    let _ = writeln!(output, "Bit Length:  {}", metadata.bit_length);
    let _ = writeln!(output, "Hamming Weight: {}", metadata.hamming_weight);
    output.push_str("---\n");
    output.push_str("Analysis:\n");

    for result in results {
        let symbol = result.status.symbol();
        let details = result.details.as_deref().unwrap_or("");
        if details.is_empty() {
            let _ = writeln!(output, "  {} {}: {}", symbol, result.analyzer, result.status.as_str().to_uppercase());
        } else {
            let _ = writeln!(output, "  {} {}: {} ({})", symbol, result.analyzer, result.status.as_str().to_uppercase(), details);
        }
    }

    output
}

pub fn format_results_json(metadata: &KeyMetadata, results: &[AnalysisResult]) -> String {
    let results_json: Vec<String> = results
        .iter()
        .map(|r| {
            let details = r.details.as_ref()
                .map(|d| format!(", \"details\": \"{}\"", escape_json(d)))
                .unwrap_or_default();
            format!(
                "    {{\"analyzer\": \"{}\", \"status\": \"{}\"{}}}",
                r.analyzer,
                r.status.as_str(),
                details
            )
        })
        .collect();

    format!(
        r#"{{
  "private_key": "{}",
  "bit_length": {},
  "hamming_weight": {},
  "leading_zeros": {},
  "results": [
{}
  ]
}}"#,
        metadata.hex,
        metadata.bit_length,
        metadata.hamming_weight,
        metadata.leading_zeros,
        results_json.join(",\n")
    )
}

fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(result, "\\u{:04x}", c as u32);
            }
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::AnalysisStatus;

    #[test]
    fn test_format_results() {
        let metadata = KeyMetadata {
            hex: "abc123".to_string(),
            bit_length: 256,
            hamming_weight: 128,
            leading_zeros: 0,
        };

        let results = vec![
            AnalysisResult {
                analyzer: "test",
                status: AnalysisStatus::Confirmed,
                details: Some("seed = 42".to_string()),
            },
        ];

        let output = format_results(&metadata, &results);
        assert!(output.contains("Private Key: abc123"));
        assert!(output.contains("CONFIRMED"));
        assert!(output.contains("seed = 42"));
    }

    #[test]
    fn test_format_json() {
        let metadata = KeyMetadata {
            hex: "abc123".to_string(),
            bit_length: 256,
            hamming_weight: 128,
            leading_zeros: 0,
        };

        let results = vec![
            AnalysisResult {
                analyzer: "test",
                status: AnalysisStatus::Confirmed,
                details: Some("seed = 42".to_string()),
            },
        ];

        let output = format_results_json(&metadata, &results);
        assert!(output.contains("\"private_key\": \"abc123\""));
        assert!(output.contains("\"status\": \"confirmed\""));
    }
}
