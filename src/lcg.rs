//! Linear Congruential Generator (LCG) implementation.
//!
//! LCGs are weak PRNGs with the formula: next = (a * prev + c) mod m
//! They have only 31-32 bits of state, making them fully searchable.
//!
//! This module provides common LCG logic shared between transform and analyzer.

/// Endianness for converting LCG state to bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LcgEndian {
    #[default]
    Big,
    Little,
}

impl LcgEndian {
    /// Parse endianness from string ("be" or "le").
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "be" | "big" => Some(LcgEndian::Big),
            "le" | "little" => Some(LcgEndian::Little),
            _ => None,
        }
    }

    /// Short name for display.
    pub fn as_str(&self) -> &'static str {
        match self {
            LcgEndian::Big => "be",
            LcgEndian::Little => "le",
        }
    }
}

/// Parameters for an LCG variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LcgVariant {
    /// Human-readable name
    pub name: &'static str,
    /// Multiplier (a)
    pub a: u64,
    /// Increment (c)
    pub c: u64,
    /// Modulus (m)
    pub m: u64,
}

impl LcgVariant {
    /// Maximum seed value for this variant.
    pub fn max_seed(&self) -> u64 {
        self.m - 1
    }

    /// Parse variant from string name.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "glibc" => Some(GLIBC),
            "minstd" => Some(MINSTD),
            "msvc" => Some(MSVC),
            "borland" => Some(BORLAND),
            _ => None,
        }
    }
}

/// glibc rand() - most common Unix LCG
/// next = (1103515245 * prev + 12345) mod 2^31
pub const GLIBC: LcgVariant = LcgVariant {
    name: "glibc",
    a: 1103515245,
    c: 12345,
    m: 1 << 31,
};

/// MINSTD (Lehmer RNG) - minimal standard RNG
/// next = (16807 * prev) mod (2^31 - 1)
pub const MINSTD: LcgVariant = LcgVariant {
    name: "minstd",
    a: 16807,
    c: 0,
    m: (1 << 31) - 1,
};

/// Microsoft Visual C++ LCG
/// next = (214013 * prev + 2531011) mod 2^32
pub const MSVC: LcgVariant = LcgVariant {
    name: "msvc",
    a: 214013,
    c: 2531011,
    m: 1 << 32,
};

/// Borland C/C++ LCG
/// next = (22695477 * prev + 1) mod 2^32
pub const BORLAND: LcgVariant = LcgVariant {
    name: "borland",
    a: 22695477,
    c: 1,
    m: 1 << 32,
};

/// All available LCG variants.
pub const ALL_VARIANTS: [LcgVariant; 4] = [GLIBC, MINSTD, MSVC, BORLAND];

/// Compute next LCG state.
#[inline]
pub fn lcg_next(state: u64, variant: &LcgVariant) -> u64 {
    (variant.a.wrapping_mul(state).wrapping_add(variant.c)) % variant.m
}

/// Generate a 32-byte key from an LCG seed.
///
/// Generates 8 consecutive LCG outputs (4 bytes each) to fill 32 bytes.
pub fn generate_key(seed: u32, variant: &LcgVariant, endian: LcgEndian) -> [u8; 32] {
    let mut state = seed as u64;
    let mut key = [0u8; 32];

    for chunk in key.chunks_mut(4) {
        state = lcg_next(state, variant);
        let bytes = match endian {
            LcgEndian::Big => (state as u32).to_be_bytes(),
            LcgEndian::Little => (state as u32).to_le_bytes(),
        };
        chunk.copy_from_slice(&bytes);
    }

    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glibc_sequence() {
        // glibc rand() with seed=1 produces known sequence
        // Verified against: srand(1); printf("%d\n", rand());
        let mut state = 1u64;
        state = lcg_next(state, &GLIBC);
        assert_eq!(state, 1103527590);

        state = lcg_next(state, &GLIBC);
        assert_eq!(state, 377401575);

        state = lcg_next(state, &GLIBC);
        assert_eq!(state, 662824084);
    }

    #[test]
    fn test_minstd_sequence() {
        // MINSTD with seed=1
        let mut state = 1u64;
        state = lcg_next(state, &MINSTD);
        assert_eq!(state, 16807);

        state = lcg_next(state, &MINSTD);
        assert_eq!(state, 282475249);
    }

    #[test]
    fn test_msvc_sequence() {
        // MSVC with seed=1
        let mut state = 1u64;
        state = lcg_next(state, &MSVC);
        assert_eq!(state, 2745024);
    }

    #[test]
    fn test_borland_sequence() {
        // Borland with seed=1
        let mut state = 1u64;
        state = lcg_next(state, &BORLAND);
        assert_eq!(state, 22695478);
    }

    #[test]
    fn test_generate_key_deterministic() {
        let key1 = generate_key(12345, &GLIBC, LcgEndian::Big);
        let key2 = generate_key(12345, &GLIBC, LcgEndian::Big);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_generate_key_different_seeds() {
        let key1 = generate_key(1, &GLIBC, LcgEndian::Big);
        let key2 = generate_key(2, &GLIBC, LcgEndian::Big);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_generate_key_different_variants() {
        let key1 = generate_key(1, &GLIBC, LcgEndian::Big);
        let key2 = generate_key(1, &MINSTD, LcgEndian::Big);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_generate_key_different_endian() {
        let key_be = generate_key(1, &GLIBC, LcgEndian::Big);
        let key_le = generate_key(1, &GLIBC, LcgEndian::Little);
        assert_ne!(key_be, key_le);
    }

    #[test]
    fn test_variant_from_str() {
        assert_eq!(LcgVariant::from_str("glibc"), Some(GLIBC));
        assert_eq!(LcgVariant::from_str("GLIBC"), Some(GLIBC));
        assert_eq!(LcgVariant::from_str("minstd"), Some(MINSTD));
        assert_eq!(LcgVariant::from_str("msvc"), Some(MSVC));
        assert_eq!(LcgVariant::from_str("borland"), Some(BORLAND));
        assert_eq!(LcgVariant::from_str("unknown"), None);
    }

    #[test]
    fn test_endian_from_str() {
        assert_eq!(LcgEndian::from_str("be"), Some(LcgEndian::Big));
        assert_eq!(LcgEndian::from_str("le"), Some(LcgEndian::Little));
        assert_eq!(LcgEndian::from_str("big"), Some(LcgEndian::Big));
        assert_eq!(LcgEndian::from_str("little"), Some(LcgEndian::Little));
        assert_eq!(LcgEndian::from_str("invalid"), None);
    }

    #[test]
    fn test_max_seed() {
        assert_eq!(GLIBC.max_seed(), (1 << 31) - 1);
        assert_eq!(MINSTD.max_seed(), (1 << 31) - 2);
        assert_eq!(MSVC.max_seed(), u32::MAX as u64);
        assert_eq!(BORLAND.max_seed(), u32::MAX as u64);
    }
}
