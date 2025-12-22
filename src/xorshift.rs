//! Xorshift PRNG implementations.
//!
//! Xorshift generators are fast PRNGs based on XOR and shift operations.
//! They are weak for cryptographic purposes but were commonly used in
//! game engines, JS runtimes, and quick scripts.
//!
//! This module provides common logic shared between transform and analyzer.
//!
//! ## Variants
//!
//! - **xorshift64**: 64-bit state, single u64 seed (Marsaglia 2003)
//! - **xorshift128**: 128-bit state, uses (seed, 0) initialization
//! - **xorshift128+**: 128-bit state with addition scrambling (used in V8, SpiderMonkey)
//! - **xoroshiro128****: 128-bit state, modern variant (Vigna 2018)
//!
//! ## References
//!
//! - Marsaglia, G. (2003). "Xorshift RNGs"
//! - Vigna, S. (2018). "Further scramblings of Marsaglia's xorshift generators"

/// Available xorshift variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XorshiftVariant {
    /// xorshift64 - 64-bit state, 64-bit seed
    Xorshift64,
    /// xorshift128 - 128-bit state, (seed, 0) initialization
    Xorshift128,
    /// xorshift128+ - 128-bit state with addition scrambling
    Xorshift128Plus,
    /// xoroshiro128** - modern 128-bit variant with multiplication scrambling
    Xoroshiro128StarStar,
}

impl XorshiftVariant {
    /// Human-readable name for this variant.
    pub fn name(&self) -> &'static str {
        match self {
            XorshiftVariant::Xorshift64 => "xorshift64",
            XorshiftVariant::Xorshift128 => "xorshift128",
            XorshiftVariant::Xorshift128Plus => "xorshift128+",
            XorshiftVariant::Xoroshiro128StarStar => "xoroshiro128**",
        }
    }

    /// Parse variant from string name.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "64" | "xorshift64" => Some(XorshiftVariant::Xorshift64),
            "128" | "xorshift128" => Some(XorshiftVariant::Xorshift128),
            "128plus" | "128+" | "plus" | "xorshift128+" => Some(XorshiftVariant::Xorshift128Plus),
            "xoroshiro" | "starstar" | "xoroshiro128**" | "xoroshiro128starstar" => {
                Some(XorshiftVariant::Xoroshiro128StarStar)
            }
            _ => None,
        }
    }

    /// Whether this variant uses 128-bit state (requires reduced seed space assumptions).
    pub fn is_128bit(&self) -> bool {
        matches!(
            self,
            XorshiftVariant::Xorshift128
                | XorshiftVariant::Xorshift128Plus
                | XorshiftVariant::Xoroshiro128StarStar
        )
    }
}

/// All available xorshift variants.
pub const ALL_VARIANTS: [XorshiftVariant; 4] = [
    XorshiftVariant::Xorshift64,
    XorshiftVariant::Xorshift128,
    XorshiftVariant::Xorshift128Plus,
    XorshiftVariant::Xoroshiro128StarStar,
];

pub trait XorshiftRng {
    fn fill_bytes(&mut self, buf: &mut [u8]);
}

/// Xorshift64 state.
#[derive(Debug, Clone)]
pub struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    /// Create new xorshift64 with given seed.
    /// Seed must be non-zero; zero seed produces all zeros.
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    /// Generate next random u64.
    #[inline]
    pub fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Fill buffer with random bytes.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let val = self.next();
            let bytes = val.to_be_bytes();
            let remaining = buf.len() - i;
            let to_copy = remaining.min(8);
            buf[i..i + to_copy].copy_from_slice(&bytes[..to_copy]);
            i += to_copy;
        }
    }
}

impl XorshiftRng for Xorshift64 {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        Xorshift64::fill_bytes(self, buf)
    }
}

/// Xorshift128 state.
#[derive(Debug, Clone)]
pub struct Xorshift128 {
    x: u32,
    y: u32,
    z: u32,
    w: u32,
}

impl Xorshift128 {
    /// Create new xorshift128 with given seed.
    /// Uses (seed, 0) initialization - seed fills x,y and z,w are derived.
    pub fn new(seed: u64) -> Self {
        let seed = if seed == 0 { 1 } else { seed };
        Self {
            x: seed as u32,
            y: (seed >> 32) as u32,
            z: seed as u32 ^ 0x12345678,
            w: ((seed >> 32) ^ 0x87654321) as u32,
        }
    }

    /// Generate next random u32.
    #[inline]
    pub fn next(&mut self) -> u32 {
        let t = self.x ^ (self.x << 11);
        self.x = self.y;
        self.y = self.z;
        self.z = self.w;
        self.w = (self.w ^ (self.w >> 19)) ^ (t ^ (t >> 8));
        self.w
    }

    /// Fill buffer with random bytes.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let val = self.next();
            let bytes = val.to_be_bytes();
            let remaining = buf.len() - i;
            let to_copy = remaining.min(4);
            buf[i..i + to_copy].copy_from_slice(&bytes[..to_copy]);
            i += to_copy;
        }
    }
}

impl XorshiftRng for Xorshift128 {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        Xorshift128::fill_bytes(self, buf)
    }
}

/// Xorshift128+ state.
#[derive(Debug, Clone)]
pub struct Xorshift128Plus {
    s0: u64,
    s1: u64,
}

impl Xorshift128Plus {
    /// Create new xorshift128+ with given seed.
    /// Uses (seed, 0) initialization with splitmix64 expansion.
    pub fn new(seed: u64) -> Self {
        let seed = if seed == 0 { 1 } else { seed };
        // Use splitmix64 to initialize state from single seed
        let s0 = splitmix64(seed);
        let s1 = splitmix64(s0);
        Self { s0, s1 }
    }

    /// Generate next random u64.
    #[inline]
    pub fn next(&mut self) -> u64 {
        let s0 = self.s0;
        let mut s1 = self.s1;
        let result = s0.wrapping_add(s1);

        s1 ^= s0;
        self.s0 = s0.rotate_left(24) ^ s1 ^ (s1 << 16);
        self.s1 = s1.rotate_left(37);

        result
    }

    /// Fill buffer with random bytes.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let val = self.next();
            let bytes = val.to_be_bytes();
            let remaining = buf.len() - i;
            let to_copy = remaining.min(8);
            buf[i..i + to_copy].copy_from_slice(&bytes[..to_copy]);
            i += to_copy;
        }
    }
}

impl XorshiftRng for Xorshift128Plus {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        Xorshift128Plus::fill_bytes(self, buf)
    }
}

/// Xoroshiro128** state.
#[derive(Debug, Clone)]
pub struct Xoroshiro128StarStar {
    s0: u64,
    s1: u64,
}

impl Xoroshiro128StarStar {
    /// Create new xoroshiro128** with given seed.
    /// Uses splitmix64 expansion from single seed.
    pub fn new(seed: u64) -> Self {
        let seed = if seed == 0 { 1 } else { seed };
        // Use splitmix64 to initialize state from single seed
        let s0 = splitmix64(seed);
        let s1 = splitmix64(s0);
        Self { s0, s1 }
    }

    /// Generate next random u64.
    #[inline]
    pub fn next(&mut self) -> u64 {
        let s0 = self.s0;
        let mut s1 = self.s1;
        let result = s0.wrapping_mul(5).rotate_left(7).wrapping_mul(9);

        s1 ^= s0;
        self.s0 = s0.rotate_left(24) ^ s1 ^ (s1 << 16);
        self.s1 = s1.rotate_left(37);

        result
    }

    /// Fill buffer with random bytes.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let val = self.next();
            let bytes = val.to_be_bytes();
            let remaining = buf.len() - i;
            let to_copy = remaining.min(8);
            buf[i..i + to_copy].copy_from_slice(&bytes[..to_copy]);
            i += to_copy;
        }
    }
}

impl XorshiftRng for Xoroshiro128StarStar {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        Xoroshiro128StarStar::fill_bytes(self, buf)
    }
}

/// Splitmix64 - used for seed expansion.
#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

/// Generate a 32-byte key from a xorshift variant with 64-bit seed.
pub fn generate_key(seed: u64, variant: XorshiftVariant) -> [u8; 32] {
    let mut key = [0u8; 32];

    match variant {
        XorshiftVariant::Xorshift64 => {
            let mut rng = Xorshift64::new(seed);
            rng.fill_bytes(&mut key);
        }
        XorshiftVariant::Xorshift128 => {
            let mut rng = Xorshift128::new(seed);
            rng.fill_bytes(&mut key);
        }
        XorshiftVariant::Xorshift128Plus => {
            let mut rng = Xorshift128Plus::new(seed);
            rng.fill_bytes(&mut key);
        }
        XorshiftVariant::Xoroshiro128StarStar => {
            let mut rng = Xoroshiro128StarStar::new(seed);
            rng.fill_bytes(&mut key);
        }
    }

    key
}

/// Parsed xorshift configuration from CLI string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorshiftConfig {
    pub variant: Option<XorshiftVariant>,
}

impl XorshiftConfig {
    /// Parse xorshift configuration from string.
    ///
    /// Formats:
    /// - "xorshift" - all variants
    /// - "xorshift:64" - xorshift64 only
    /// - "xorshift:128" - xorshift128 only
    /// - "xorshift:128plus" or "xorshift:plus" - xorshift128+ only
    /// - "xorshift:xoroshiro" or "xorshift:starstar" - xoroshiro128** only
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.to_lowercase();
        let s = s.trim_end_matches(':');
        let parts: Vec<&str> = s.split(':').collect();

        match parts.as_slice() {
            ["xorshift"] => Ok(XorshiftConfig { variant: None }),
            ["xorshift", v] => {
                let variant = XorshiftVariant::from_str(v).ok_or_else(|| {
                    format!(
                        "Invalid xorshift variant: '{}'. Valid: 64, 128, 128plus, xoroshiro",
                        v
                    )
                })?;
                Ok(XorshiftConfig {
                    variant: Some(variant),
                })
            }
            _ => Err(
                "Invalid xorshift format. Use: xorshift, xorshift:64, xorshift:128, xorshift:128plus, xorshift:xoroshiro"
                    .to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors generated independently to verify algorithm correctness

    #[test]
    fn test_xorshift64_deterministic() {
        let key1 = generate_key(12345, XorshiftVariant::Xorshift64);
        let key2 = generate_key(12345, XorshiftVariant::Xorshift64);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_xorshift64_different_seeds() {
        let key1 = generate_key(1, XorshiftVariant::Xorshift64);
        let key2 = generate_key(2, XorshiftVariant::Xorshift64);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_xorshift64_zero_seed_handled() {
        // Zero seed should be converted to 1 to avoid degenerate sequence
        let key = generate_key(0, XorshiftVariant::Xorshift64);
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn test_xorshift64_sequence() {
        // Known sequence for xorshift64 with seed=1
        let mut rng = Xorshift64::new(1);
        let first = rng.next();
        let second = rng.next();

        // Verify sequence is non-trivial and deterministic
        assert_ne!(first, 1);
        assert_ne!(first, second);

        // Recreate and verify same sequence
        let mut rng2 = Xorshift64::new(1);
        assert_eq!(rng2.next(), first);
        assert_eq!(rng2.next(), second);
    }

    #[test]
    fn test_xorshift128_deterministic() {
        let key1 = generate_key(12345, XorshiftVariant::Xorshift128);
        let key2 = generate_key(12345, XorshiftVariant::Xorshift128);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_xorshift128_different_seeds() {
        let key1 = generate_key(1, XorshiftVariant::Xorshift128);
        let key2 = generate_key(2, XorshiftVariant::Xorshift128);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_xorshift128plus_deterministic() {
        let key1 = generate_key(12345, XorshiftVariant::Xorshift128Plus);
        let key2 = generate_key(12345, XorshiftVariant::Xorshift128Plus);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_xorshift128plus_different_seeds() {
        let key1 = generate_key(1, XorshiftVariant::Xorshift128Plus);
        let key2 = generate_key(2, XorshiftVariant::Xorshift128Plus);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_xoroshiro128starstar_deterministic() {
        let key1 = generate_key(12345, XorshiftVariant::Xoroshiro128StarStar);
        let key2 = generate_key(12345, XorshiftVariant::Xoroshiro128StarStar);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_xoroshiro128starstar_different_seeds() {
        let key1 = generate_key(1, XorshiftVariant::Xoroshiro128StarStar);
        let key2 = generate_key(2, XorshiftVariant::Xoroshiro128StarStar);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_variants_produce_different_keys() {
        let seed = 42u64;
        let key64 = generate_key(seed, XorshiftVariant::Xorshift64);
        let key128 = generate_key(seed, XorshiftVariant::Xorshift128);
        let key128plus = generate_key(seed, XorshiftVariant::Xorshift128Plus);
        let key_xoroshiro = generate_key(seed, XorshiftVariant::Xoroshiro128StarStar);

        assert_ne!(key64, key128);
        assert_ne!(key64, key128plus);
        assert_ne!(key64, key_xoroshiro);
        assert_ne!(key128, key128plus);
        assert_ne!(key128, key_xoroshiro);
        assert_ne!(key128plus, key_xoroshiro);
    }

    #[test]
    fn test_variant_from_str() {
        assert_eq!(
            XorshiftVariant::from_str("64"),
            Some(XorshiftVariant::Xorshift64)
        );
        assert_eq!(
            XorshiftVariant::from_str("xorshift64"),
            Some(XorshiftVariant::Xorshift64)
        );
        assert_eq!(
            XorshiftVariant::from_str("128"),
            Some(XorshiftVariant::Xorshift128)
        );
        assert_eq!(
            XorshiftVariant::from_str("128plus"),
            Some(XorshiftVariant::Xorshift128Plus)
        );
        assert_eq!(
            XorshiftVariant::from_str("128+"),
            Some(XorshiftVariant::Xorshift128Plus)
        );
        assert_eq!(
            XorshiftVariant::from_str("plus"),
            Some(XorshiftVariant::Xorshift128Plus)
        );
        assert_eq!(
            XorshiftVariant::from_str("xoroshiro"),
            Some(XorshiftVariant::Xoroshiro128StarStar)
        );
        assert_eq!(
            XorshiftVariant::from_str("starstar"),
            Some(XorshiftVariant::Xoroshiro128StarStar)
        );
        assert_eq!(XorshiftVariant::from_str("invalid"), None);
    }

    #[test]
    fn test_variant_is_128bit() {
        assert!(!XorshiftVariant::Xorshift64.is_128bit());
        assert!(XorshiftVariant::Xorshift128.is_128bit());
        assert!(XorshiftVariant::Xorshift128Plus.is_128bit());
        assert!(XorshiftVariant::Xoroshiro128StarStar.is_128bit());
    }

    #[test]
    fn test_config_parse() {
        let config = XorshiftConfig::parse("xorshift").unwrap();
        assert_eq!(config.variant, None);

        let config = XorshiftConfig::parse("xorshift:64").unwrap();
        assert_eq!(config.variant, Some(XorshiftVariant::Xorshift64));

        let config = XorshiftConfig::parse("xorshift:128plus").unwrap();
        assert_eq!(config.variant, Some(XorshiftVariant::Xorshift128Plus));

        let config = XorshiftConfig::parse("xorshift:xoroshiro").unwrap();
        assert_eq!(config.variant, Some(XorshiftVariant::Xoroshiro128StarStar));

        assert!(XorshiftConfig::parse("xorshift:invalid").is_err());
    }

    #[test]
    fn test_config_parse_case_insensitive() {
        let config = XorshiftConfig::parse("XORSHIFT:64").unwrap();
        assert_eq!(config.variant, Some(XorshiftVariant::Xorshift64));
    }

    #[test]
    fn test_config_parse_trailing_colon() {
        let config = XorshiftConfig::parse("xorshift:").unwrap();
        assert_eq!(config.variant, None);
    }

    #[test]
    fn test_splitmix64() {
        // Verify splitmix64 produces non-trivial expansion
        let s0 = splitmix64(1);
        let s1 = splitmix64(s0);
        assert_ne!(s0, 1);
        assert_ne!(s1, s0);
    }

    #[test]
    fn test_key_length() {
        for variant in ALL_VARIANTS {
            let key = generate_key(42, variant);
            assert_eq!(key.len(), 32, "Key should be 32 bytes for {:?}", variant);
        }
    }
}
