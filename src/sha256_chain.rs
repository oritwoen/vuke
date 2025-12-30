//! SHA256 Chain Generator implementation.
//!
//! Some key generators use deterministic SHA256 chains:
//! - Iterated: key[n] = SHA256(key[n-1])
//! - IndexedBinary: key[n] = SHA256(seed || n as bytes)
//! - IndexedString: key[n] = SHA256(seed || "n")
//!
//! This is a plausible generation method for puzzle sequences like BTC1000.

use sha2::{Digest, Sha256};

/// Endianness for index bytes in IndexedBinary variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sha256ChainEndian {
    #[default]
    Big,
    Little,
}

impl Sha256ChainEndian {
    /// Parse endianness from string ("be" or "le").
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "be" | "big" => Some(Sha256ChainEndian::Big),
            "le" | "little" => Some(Sha256ChainEndian::Little),
            _ => None,
        }
    }

    /// Short name for display.
    pub fn as_str(&self) -> &'static str {
        match self {
            Sha256ChainEndian::Big => "be",
            Sha256ChainEndian::Little => "le",
        }
    }
}

/// SHA256 chain generation variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha256ChainVariant {
    /// key[n] = SHA256(key[n-1]), where key[0] = SHA256(seed)
    Iterated,
    /// key[n] = SHA256(seed || n as bytes)
    IndexedBinary { big_endian: bool },
    /// key[n] = SHA256(seed || "n")
    IndexedString,
}

impl Sha256ChainVariant {
    /// Human-readable name for this variant.
    pub fn name(&self) -> &'static str {
        match self {
            Sha256ChainVariant::Iterated => "iterated",
            Sha256ChainVariant::IndexedBinary { big_endian: true } => "indexed:be",
            Sha256ChainVariant::IndexedBinary { big_endian: false } => "indexed:le",
            Sha256ChainVariant::IndexedString => "counter",
        }
    }

    /// Parse variant from string name.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "iterated" => Some(Sha256ChainVariant::Iterated),
            "indexed" | "indexed:be" => Some(Sha256ChainVariant::IndexedBinary { big_endian: true }),
            "indexed:le" => Some(Sha256ChainVariant::IndexedBinary { big_endian: false }),
            "counter" => Some(Sha256ChainVariant::IndexedString),
            _ => None,
        }
    }
}

/// All available SHA256 chain variants (for testing all at once).
pub const ALL_VARIANTS: [Sha256ChainVariant; 4] = [
    Sha256ChainVariant::Iterated,
    Sha256ChainVariant::IndexedBinary { big_endian: true },
    Sha256ChainVariant::IndexedBinary { big_endian: false },
    Sha256ChainVariant::IndexedString,
];

/// Default chain depth for analysis/generation.
pub const DEFAULT_CHAIN_DEPTH: u32 = 10;

/// Generate a single key at a specific index in the chain.
///
/// For Iterated variant, this generates all keys from 0 to index.
/// For Indexed variants, this directly computes the key at index.
pub fn generate_key_at_index(seed: &[u8], variant: Sha256ChainVariant, index: u32) -> [u8; 32] {
    match variant {
        Sha256ChainVariant::Iterated => {
            // key[0] = SHA256(seed), key[n] = SHA256(key[n-1])
            let mut key: [u8; 32] = Sha256::digest(seed).into();
            for _ in 0..index {
                key = Sha256::digest(key).into();
            }
            key
        }
        Sha256ChainVariant::IndexedBinary { big_endian } => {
            // key[n] = SHA256(seed || n as bytes)
            let index_bytes = if big_endian {
                index.to_be_bytes()
            } else {
                index.to_le_bytes()
            };
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(index_bytes);
            hasher.finalize().into()
        }
        Sha256ChainVariant::IndexedString => {
            // key[n] = SHA256(seed || "n")
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(index.to_string().as_bytes());
            hasher.finalize().into()
        }
    }
}

/// Generate a chain of keys from a seed.
///
/// Returns a vector of `depth` keys starting from index 0.
pub fn generate_chain(seed: &[u8], variant: Sha256ChainVariant, depth: u32) -> Vec<[u8; 32]> {
    if depth == 0 {
        return Vec::new();
    }

    match variant {
        Sha256ChainVariant::Iterated => {
            let mut chain = Vec::with_capacity(depth as usize);
            let mut key: [u8; 32] = Sha256::digest(seed).into();
            chain.push(key);
            for _ in 1..depth {
                key = Sha256::digest(key).into();
                chain.push(key);
            }
            chain
        }
        _ => {
            (0..depth)
                .map(|i| generate_key_at_index(seed, variant, i))
                .collect()
        }
    }
}

/// Generate a chain from a 32-bit numeric seed.
///
/// The seed is converted to 4 bytes (big-endian) before hashing.
pub fn generate_chain_from_u32(seed: u32, variant: Sha256ChainVariant, depth: u32) -> Vec<[u8; 32]> {
    generate_chain(&seed.to_be_bytes(), variant, depth)
}

/// Generate a chain from a string seed.
///
/// The string is converted to UTF-8 bytes before hashing.
pub fn generate_chain_from_string(seed: &str, variant: Sha256ChainVariant, depth: u32) -> Vec<[u8; 32]> {
    generate_chain(seed.as_bytes(), variant, depth)
}

/// Parsed SHA256 chain configuration from CLI string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha256ChainConfig {
    pub variant: Option<Sha256ChainVariant>,
    pub chain_depth: u32,
}

impl Default for Sha256ChainConfig {
    fn default() -> Self {
        Self {
            variant: None,
            chain_depth: DEFAULT_CHAIN_DEPTH,
        }
    }
}

impl Sha256ChainConfig {
    /// Parse SHA256 chain configuration from string.
    ///
    /// Formats:
    /// - "sha256_chain" - all variants
    /// - "sha256_chain:iterated" - iterated hash only
    /// - "sha256_chain:indexed" - indexed binary (big-endian)
    /// - "sha256_chain:indexed:le" - indexed binary (little-endian)
    /// - "sha256_chain:indexed:be" - indexed binary (big-endian, explicit)
    /// - "sha256_chain:counter" - indexed string (counter mode)
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.to_lowercase();
        let s = s.trim_end_matches(':');
        let parts: Vec<&str> = s.split(':').collect();

        match parts.as_slice() {
            ["sha256_chain"] => Ok(Sha256ChainConfig::default()),
            ["sha256_chain", v] => {
                let variant = Self::parse_variant(v)?;
                Ok(Sha256ChainConfig {
                    variant: Some(variant),
                    chain_depth: DEFAULT_CHAIN_DEPTH,
                })
            }
            ["sha256_chain", "indexed", e] => {
                let big_endian = match *e {
                    "be" | "big" => true,
                    "le" | "little" => false,
                    _ => return Err(format!("Invalid endian: '{}'. Valid: be, le", e)),
                };
                Ok(Sha256ChainConfig {
                    variant: Some(Sha256ChainVariant::IndexedBinary { big_endian }),
                    chain_depth: DEFAULT_CHAIN_DEPTH,
                })
            }
            _ => Err(format!(
                "Invalid SHA256 chain format: '{}'. Valid: sha256_chain, sha256_chain:iterated, sha256_chain:indexed[:be|:le], sha256_chain:counter",
                s
            )),
        }
    }

    fn parse_variant(v: &str) -> Result<Sha256ChainVariant, String> {
        Sha256ChainVariant::from_str(v).ok_or_else(|| {
            format!(
                "Invalid SHA256 chain variant: '{}'. Valid: iterated, indexed, counter",
                v
            )
        })
    }

    /// Get variants to test based on configuration.
    pub fn variants_to_test(&self) -> Vec<Sha256ChainVariant> {
        match self.variant {
            Some(v) => vec![v],
            None => ALL_VARIANTS.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Endian Tests ====================

    #[test]
    fn test_endian_from_str() {
        assert_eq!(Sha256ChainEndian::from_str("be"), Some(Sha256ChainEndian::Big));
        assert_eq!(Sha256ChainEndian::from_str("le"), Some(Sha256ChainEndian::Little));
        assert_eq!(Sha256ChainEndian::from_str("big"), Some(Sha256ChainEndian::Big));
        assert_eq!(Sha256ChainEndian::from_str("little"), Some(Sha256ChainEndian::Little));
        assert_eq!(Sha256ChainEndian::from_str("BE"), Some(Sha256ChainEndian::Big));
        assert_eq!(Sha256ChainEndian::from_str("invalid"), None);
    }

    #[test]
    fn test_endian_as_str() {
        assert_eq!(Sha256ChainEndian::Big.as_str(), "be");
        assert_eq!(Sha256ChainEndian::Little.as_str(), "le");
    }

    // ==================== Variant Tests ====================

    #[test]
    fn test_variant_from_str() {
        assert_eq!(
            Sha256ChainVariant::from_str("iterated"),
            Some(Sha256ChainVariant::Iterated)
        );
        assert_eq!(
            Sha256ChainVariant::from_str("indexed"),
            Some(Sha256ChainVariant::IndexedBinary { big_endian: true })
        );
        assert_eq!(
            Sha256ChainVariant::from_str("indexed:be"),
            Some(Sha256ChainVariant::IndexedBinary { big_endian: true })
        );
        assert_eq!(
            Sha256ChainVariant::from_str("indexed:le"),
            Some(Sha256ChainVariant::IndexedBinary { big_endian: false })
        );
        assert_eq!(
            Sha256ChainVariant::from_str("counter"),
            Some(Sha256ChainVariant::IndexedString)
        );
        assert_eq!(Sha256ChainVariant::from_str("ITERATED"), Some(Sha256ChainVariant::Iterated));
        assert_eq!(Sha256ChainVariant::from_str("unknown"), None);
    }

    #[test]
    fn test_variant_name() {
        assert_eq!(Sha256ChainVariant::Iterated.name(), "iterated");
        assert_eq!(Sha256ChainVariant::IndexedBinary { big_endian: true }.name(), "indexed:be");
        assert_eq!(Sha256ChainVariant::IndexedBinary { big_endian: false }.name(), "indexed:le");
        assert_eq!(Sha256ChainVariant::IndexedString.name(), "counter");
    }

    // ==================== Key Generation Tests ====================

    #[test]
    fn test_generate_key_iterated_deterministic() {
        let seed = b"test seed";
        let key1 = generate_key_at_index(seed, Sha256ChainVariant::Iterated, 0);
        let key2 = generate_key_at_index(seed, Sha256ChainVariant::Iterated, 0);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_generate_key_iterated_chain() {
        let seed = b"test seed";
        // key[0] = SHA256(seed)
        let key0 = generate_key_at_index(seed, Sha256ChainVariant::Iterated, 0);
        let expected_key0: [u8; 32] = Sha256::digest(seed).into();
        assert_eq!(key0, expected_key0);

        // key[1] = SHA256(key[0])
        let key1 = generate_key_at_index(seed, Sha256ChainVariant::Iterated, 1);
        let expected_key1: [u8; 32] = Sha256::digest(key0).into();
        assert_eq!(key1, expected_key1);

        // key[2] = SHA256(key[1])
        let key2 = generate_key_at_index(seed, Sha256ChainVariant::Iterated, 2);
        let expected_key2: [u8; 32] = Sha256::digest(key1).into();
        assert_eq!(key2, expected_key2);
    }

    #[test]
    fn test_generate_key_indexed_binary() {
        let seed = b"test";
        let variant_be = Sha256ChainVariant::IndexedBinary { big_endian: true };
        let variant_le = Sha256ChainVariant::IndexedBinary { big_endian: false };

        // key[5] = SHA256(seed || 5 as bytes)
        let key_be = generate_key_at_index(seed, variant_be, 5);
        let key_le = generate_key_at_index(seed, variant_le, 5);

        // Verify they're different due to endianness
        assert_ne!(key_be, key_le);

        // Verify BE computation manually
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(5u32.to_be_bytes());
        let expected_be: [u8; 32] = hasher.finalize().into();
        assert_eq!(key_be, expected_be);

        // Verify LE computation manually
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(5u32.to_le_bytes());
        let expected_le: [u8; 32] = hasher.finalize().into();
        assert_eq!(key_le, expected_le);
    }

    #[test]
    fn test_generate_key_indexed_string() {
        let seed = b"test";
        let variant = Sha256ChainVariant::IndexedString;

        // key[42] = SHA256(seed || "42")
        let key = generate_key_at_index(seed, variant, 42);

        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(b"42");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(key, expected);
    }

    #[test]
    fn test_generate_chain_length() {
        let seed = b"seed";
        let chain = generate_chain(seed, Sha256ChainVariant::Iterated, 5);
        assert_eq!(chain.len(), 5);

        let chain = generate_chain(seed, Sha256ChainVariant::IndexedBinary { big_endian: true }, 10);
        assert_eq!(chain.len(), 10);
    }

    #[test]
    fn test_generate_chain_consistency() {
        let seed = b"seed";
        let variant = Sha256ChainVariant::Iterated;

        let chain = generate_chain(seed, variant, 5);

        // Each key in chain should match generate_key_at_index
        for (i, key) in chain.iter().enumerate() {
            let expected = generate_key_at_index(seed, variant, i as u32);
            assert_eq!(*key, expected, "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_generate_chain_from_u32() {
        let seed = 12345u32;
        let chain = generate_chain_from_u32(seed, Sha256ChainVariant::Iterated, 3);

        // Should be same as generate_chain with seed bytes
        let expected = generate_chain(&seed.to_be_bytes(), Sha256ChainVariant::Iterated, 3);
        assert_eq!(chain, expected);
    }

    #[test]
    fn test_generate_chain_from_string() {
        let seed = "password123";
        let chain = generate_chain_from_string(seed, Sha256ChainVariant::Iterated, 3);

        // Should be same as generate_chain with string bytes
        let expected = generate_chain(seed.as_bytes(), Sha256ChainVariant::Iterated, 3);
        assert_eq!(chain, expected);
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let key1 = generate_key_at_index(b"seed1", Sha256ChainVariant::Iterated, 0);
        let key2 = generate_key_at_index(b"seed2", Sha256ChainVariant::Iterated, 0);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_variants_different_keys() {
        let seed = b"test";
        let key_iter = generate_key_at_index(seed, Sha256ChainVariant::Iterated, 1);
        let key_idx = generate_key_at_index(seed, Sha256ChainVariant::IndexedBinary { big_endian: true }, 1);
        let key_str = generate_key_at_index(seed, Sha256ChainVariant::IndexedString, 1);

        assert_ne!(key_iter, key_idx);
        assert_ne!(key_iter, key_str);
        assert_ne!(key_idx, key_str);
    }

    #[test]
    fn test_zero_depth_chain() {
        let chain = generate_chain(b"seed", Sha256ChainVariant::Iterated, 0);
        assert!(chain.is_empty());
    }

    #[test]
    fn test_empty_seed() {
        // Empty seed should still work
        let key = generate_key_at_index(b"", Sha256ChainVariant::Iterated, 0);
        let expected: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(key, expected);
    }

    // ==================== Config Parser Tests ====================

    #[test]
    fn test_parse_sha256_chain_only() {
        let config = Sha256ChainConfig::parse("sha256_chain").unwrap();
        assert_eq!(config.variant, None);
        assert_eq!(config.chain_depth, DEFAULT_CHAIN_DEPTH);
    }

    #[test]
    fn test_parse_sha256_chain_iterated() {
        let config = Sha256ChainConfig::parse("sha256_chain:iterated").unwrap();
        assert_eq!(config.variant, Some(Sha256ChainVariant::Iterated));
    }

    #[test]
    fn test_parse_sha256_chain_indexed() {
        let config = Sha256ChainConfig::parse("sha256_chain:indexed").unwrap();
        assert_eq!(
            config.variant,
            Some(Sha256ChainVariant::IndexedBinary { big_endian: true })
        );
    }

    #[test]
    fn test_parse_sha256_chain_indexed_be() {
        let config = Sha256ChainConfig::parse("sha256_chain:indexed:be").unwrap();
        assert_eq!(
            config.variant,
            Some(Sha256ChainVariant::IndexedBinary { big_endian: true })
        );
    }

    #[test]
    fn test_parse_sha256_chain_indexed_le() {
        let config = Sha256ChainConfig::parse("sha256_chain:indexed:le").unwrap();
        assert_eq!(
            config.variant,
            Some(Sha256ChainVariant::IndexedBinary { big_endian: false })
        );
    }

    #[test]
    fn test_parse_sha256_chain_counter() {
        let config = Sha256ChainConfig::parse("sha256_chain:counter").unwrap();
        assert_eq!(config.variant, Some(Sha256ChainVariant::IndexedString));
    }

    #[test]
    fn test_parse_case_insensitive() {
        let config = Sha256ChainConfig::parse("SHA256_CHAIN:ITERATED").unwrap();
        assert_eq!(config.variant, Some(Sha256ChainVariant::Iterated));
    }

    #[test]
    fn test_parse_trailing_colon() {
        let config = Sha256ChainConfig::parse("sha256_chain:").unwrap();
        assert_eq!(config.variant, None);
    }

    #[test]
    fn test_parse_invalid_variant() {
        let result = Sha256ChainConfig::parse("sha256_chain:invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid SHA256 chain variant"));
    }

    #[test]
    fn test_parse_invalid_endian() {
        let result = Sha256ChainConfig::parse("sha256_chain:indexed:xyz");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid endian"));
    }

    #[test]
    fn test_variants_to_test_all() {
        let config = Sha256ChainConfig::default();
        let variants = config.variants_to_test();
        assert_eq!(variants.len(), 4);
    }

    #[test]
    fn test_variants_to_test_specific() {
        let config = Sha256ChainConfig {
            variant: Some(Sha256ChainVariant::Iterated),
            chain_depth: 10,
        };
        let variants = config.variants_to_test();
        assert_eq!(variants.len(), 1);
        assert_eq!(variants[0], Sha256ChainVariant::Iterated);
    }
}
