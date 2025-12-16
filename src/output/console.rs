//! Console output handler.

use anyhow::Result;
use std::io::{self, Write};
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

    fn hit(&self, source: &str, transform: &str, derived: &DerivedKey, match_info: &MatchInfo) -> Result<()> {
        let mut w = self.writer.lock().unwrap();

        writeln!(w, "\n========== HIT ==========")?;
        writeln!(w, "Source: {}", source)?;
        writeln!(w, "Transform: {}", transform)?;
        writeln!(w, "Matched: {} ({})", match_info.address, match_info.address_type.as_str())?;
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
