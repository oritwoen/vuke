//! MT19937-64 (64-bit seed) implementation.
//!
//! MT19937-64 is the 64-bit variant of the Mersenne Twister PRNG.
//! Unlike the standard MT19937 which uses 32-bit seeds, this variant
//! uses 64-bit seeds and produces 64-bit output.
//!
//! This module provides common logic shared between transform and analyzer.

use rand_mt::Mt64;

/// Generate a 32-byte key from MT19937-64 with 64-bit seed.
///
/// Creates an MT19937-64 RNG seeded with the given value and fills
/// a 32-byte buffer with random bytes.
pub fn generate_key(seed: u64) -> [u8; 32] {
    let mut rng = Mt64::new(seed);
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let key1 = generate_key(12345);
        let key2 = generate_key(12345);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_seeds() {
        let key1 = generate_key(1);
        let key2 = generate_key(2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_zero_seed() {
        let key = generate_key(0);
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn test_max_seed() {
        let key = generate_key(u64::MAX);
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn test_key_length() {
        let key = generate_key(42);
        assert_eq!(key.len(), 32);
    }
}
