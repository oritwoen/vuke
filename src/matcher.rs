//! Address matcher - check if derived keys match target addresses.

use anyhow::Result;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::derive::DerivedKey;

/// Match information when a key is found.
#[derive(Debug, Clone)]
pub struct MatchInfo {
    /// Which address type matched
    pub address_type: AddressType,
    /// The matched address
    pub address: String,
}

/// Address format types.
#[derive(Debug, Clone, Copy)]
pub enum AddressType {
    P2pkhCompressed,
    P2pkhUncompressed,
    P2wpkh,
}

impl AddressType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressType::P2pkhCompressed => "p2pkh_compressed",
            AddressType::P2pkhUncompressed => "p2pkh_uncompressed",
            AddressType::P2wpkh => "p2wpkh",
        }
    }
}

/// Matcher for checking derived keys against target addresses.
pub struct Matcher {
    targets: HashSet<String>,
}

impl Matcher {
    /// Load targets from file (one address per line).
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut targets = HashSet::new();
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let l = line?;
            let s = l.trim();
            if !s.is_empty() && !s.starts_with('#') {
                targets.insert(s.to_string());
            }
        }

        Ok(Self { targets })
    }

    /// Create matcher from address list.
    pub fn from_addresses(addresses: Vec<String>) -> Self {
        Self {
            targets: addresses.into_iter().collect(),
        }
    }

    /// Check if any derived address matches targets.
    /// Returns MatchInfo if found.
    pub fn check(&self, derived: &DerivedKey) -> Option<MatchInfo> {
        // Check P2PKH compressed
        if self.targets.contains(&derived.p2pkh_compressed) {
            return Some(MatchInfo {
                address_type: AddressType::P2pkhCompressed,
                address: derived.p2pkh_compressed.clone(),
            });
        }

        // Check P2PKH uncompressed
        if self.targets.contains(&derived.p2pkh_uncompressed) {
            return Some(MatchInfo {
                address_type: AddressType::P2pkhUncompressed,
                address: derived.p2pkh_uncompressed.clone(),
            });
        }

        // Check P2WPKH
        if self.targets.contains(&derived.p2wpkh) {
            return Some(MatchInfo {
                address_type: AddressType::P2wpkh,
                address: derived.p2wpkh.clone(),
            });
        }

        None
    }

    /// Number of target addresses.
    pub fn count(&self) -> usize {
        self.targets.len()
    }

    /// Check if targets set is empty.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::KeyDeriver;

    #[test]
    fn test_matcher_check() {
        // Known key: "correct horse battery staple" SHA256
        let key: [u8; 32] = [
            0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
            0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
            0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
            0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
        ];

        let deriver = KeyDeriver::new();
        let derived = deriver.derive(&key);

        // Should match uncompressed P2PKH
        let matcher = Matcher::from_addresses(vec![
            "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T".to_string(),
        ]);

        let result = matcher.check(&derived);
        assert!(result.is_some());

        let info = result.unwrap();
        assert!(matches!(info.address_type, AddressType::P2pkhUncompressed));
        assert_eq!(info.address, "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T");
    }

    #[test]
    fn test_matcher_no_match() {
        let key = [1u8; 32];
        let deriver = KeyDeriver::new();
        let derived = deriver.derive(&key);

        let matcher = Matcher::from_addresses(vec![
            "1NonExistentAddress".to_string(),
        ]);

        assert!(matcher.check(&derived).is_none());
    }
}
