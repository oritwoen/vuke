//! Console output handler.

use anyhow::Result;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

use super::Output;
use crate::derive::DerivedKey;
use crate::matcher::MatchInfo;

/// Console output - prints to stdout/stderr.
pub struct ConsoleOutput {
    writer: Mutex<Box<dyn Write + Send>>,
    verbose: bool,
}

impl ConsoleOutput {
    /// Create console output to stdout.
    pub fn new() -> Self {
        Self {
            writer: Mutex::new(Box::new(io::stdout())),
            verbose: false,
        }
    }

    /// Create verbose console output.
    pub fn verbose() -> Self {
        Self {
            writer: Mutex::new(Box::new(io::stdout())),
            verbose: true,
        }
    }

    /// Create output to file.
    pub fn to_file(path: &Path) -> Result<Self> {
        let file = File::create(path)?;
        Ok(Self {
            writer: Mutex::new(Box::new(BufWriter::new(file))),
            verbose: false,
        })
    }

    /// Create verbose output to file.
    pub fn to_file_verbose(path: &Path) -> Result<Self> {
        let file = File::create(path)?;
        Ok(Self {
            writer: Mutex::new(Box::new(BufWriter::new(file))),
            verbose: true,
        })
    }
}

impl Default for ConsoleOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl Output for ConsoleOutput {
    fn key(&self, source: &str, transform: &str, derived: &DerivedKey) -> Result<()> {
        let mut w = self.writer.lock().unwrap();

        if self.verbose {
            writeln!(w, "---")?;
            writeln!(w, "source: {}", source)?;
            writeln!(w, "transform: {}", transform)?;
            writeln!(w, "private_key: {}", derived.private_key_hex)?;
            writeln!(w, "wif_compressed: {}", derived.wif_compressed)?;
            writeln!(w, "wif_uncompressed: {}", derived.wif_uncompressed)?;
            writeln!(w, "p2pkh_compressed: {}", derived.p2pkh_compressed)?;
            writeln!(w, "p2pkh_uncompressed: {}", derived.p2pkh_uncompressed)?;
            writeln!(w, "p2wpkh: {}", derived.p2wpkh)?;
        } else {
            // Compact format: source,transform,privkey,address_compressed
            writeln!(
                w,
                "{},{},{},{}",
                source, transform, derived.private_key_hex, derived.p2pkh_compressed
            )?;
        }

        Ok(())
    }

    fn hit(
        &self,
        source: &str,
        transform: &str,
        derived: &DerivedKey,
        match_info: &MatchInfo,
    ) -> Result<()> {
        let mut w = self.writer.lock().unwrap();

        writeln!(w, "\n========== HIT ==========")?;
        writeln!(w, "Source: {}", source)?;
        writeln!(w, "Transform: {}", transform)?;
        writeln!(
            w,
            "Matched: {} ({})",
            match_info.address,
            match_info.address_type.as_str()
        )?;
        writeln!(w, "---")?;
        writeln!(w, "Private Key: {}", derived.private_key_hex)?;
        writeln!(w, "WIF (compressed): {}", derived.wif_compressed)?;
        writeln!(w, "WIF (uncompressed): {}", derived.wif_uncompressed)?;
        writeln!(w, "---")?;
        writeln!(w, "P2PKH (compressed): {}", derived.p2pkh_compressed)?;
        writeln!(w, "P2PKH (uncompressed): {}", derived.p2pkh_uncompressed)?;
        writeln!(w, "P2WPKH: {}", derived.p2wpkh)?;
        writeln!(w, "=========================")?;

        Ok(())
    }

    fn flush(&self) -> Result<()> {
        let mut w = self.writer.lock().unwrap();
        w.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn make_test_key() -> DerivedKey {
        DerivedKey {
            raw: [
                0xab, 0xc1, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            private_key_hex: "abc123".to_string(),
            private_key_decimal: "123".to_string(),
            private_key_binary: "101".to_string(),
            bit_length: 8,
            hamming_weight: 3,
            leading_zeros: 0,
            pubkey_compressed: "02abc".to_string(),
            pubkey_uncompressed: "04abc".to_string(),
            wif_compressed: "WIF_C".to_string(),
            wif_uncompressed: "WIF_U".to_string(),
            p2pkh_compressed: "1Address".to_string(),
            p2pkh_uncompressed: "1Uncompressed".to_string(),
            p2wpkh: "bc1q...".to_string(),
        }
    }

    #[test]
    fn test_to_file_writes_compact_format() {
        let temp = NamedTempFile::new().unwrap();
        let output = ConsoleOutput::to_file(temp.path()).unwrap();

        output
            .key("test_source", "sha256", &make_test_key())
            .unwrap();
        output.flush().unwrap();

        let content = std::fs::read_to_string(temp.path()).unwrap();
        assert!(content.contains("test_source,sha256,abc123,1Address"));
    }

    #[test]
    fn test_to_file_verbose_writes_yaml_format() {
        let temp = NamedTempFile::new().unwrap();
        let output = ConsoleOutput::to_file_verbose(temp.path()).unwrap();

        output
            .key("test_source", "sha256", &make_test_key())
            .unwrap();
        output.flush().unwrap();

        let content = std::fs::read_to_string(temp.path()).unwrap();
        assert!(content.contains("source: test_source"));
        assert!(content.contains("transform: sha256"));
        assert!(content.contains("private_key: abc123"));
        assert!(content.contains("p2pkh_compressed: 1Address"));
    }
}
