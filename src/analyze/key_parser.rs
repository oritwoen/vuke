//! Private key parsing from various formats.

use anyhow::{anyhow, Result};
use bitcoin::PrivateKey;
use num_bigint::BigUint;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum ParseError {
    InvalidHex(String),
    InvalidWif(String),
    InvalidDecimal(String),
    UnknownFormat,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidHex(e) => write!(f, "invalid hex: {}", e),
            ParseError::InvalidWif(e) => write!(f, "invalid WIF: {}", e),
            ParseError::InvalidDecimal(e) => write!(f, "invalid decimal: {}", e),
            ParseError::UnknownFormat => write!(f, "unknown key format"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a private key from hex, WIF, or decimal format.
pub fn parse_private_key(input: &str) -> Result<[u8; 32]> {
    let input = input.trim();

    if let Some(key) = try_parse_wif(input) {
        return Ok(key);
    }

    if let Some(key) = try_parse_hex(input) {
        return Ok(key);
    }

    if let Some(key) = try_parse_decimal(input) {
        return Ok(key);
    }

    Err(anyhow!(ParseError::UnknownFormat))
}

fn try_parse_hex(input: &str) -> Option<[u8; 32]> {
    let input = input.strip_prefix("0x").unwrap_or(input);

    if input.is_empty() || input.len() > 64 {
        return None;
    }

    if !input.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let padded = format!("{:0>64}", input);
    let bytes = hex::decode(&padded).ok()?;
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

fn try_parse_wif(input: &str) -> Option<[u8; 32]> {
    let first_char = input.chars().next()?;

    // Mainnet: 5 (uncompressed), K/L (compressed)
    // Testnet: 9 (uncompressed), c (compressed)
    if !matches!(first_char, '5' | 'K' | 'L' | '9' | 'c') {
        return None;
    }

    let private_key = PrivateKey::from_str(input).ok()?;
    Some(private_key.inner.secret_bytes())
}

fn try_parse_decimal(input: &str) -> Option<[u8; 32]> {
    if !input.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    if input.is_empty() {
        return None;
    }

    let value = BigUint::parse_bytes(input.as_bytes(), 10)?;
    let bytes = value.to_bytes_be();

    if bytes.len() > 32 {
        return None;
    }

    let mut key = [0u8; 32];
    let start = 32 - bytes.len();
    key[start..].copy_from_slice(&bytes);

    if !is_valid_secp256k1_scalar(&key) {
        return None;
    }

    Some(key)
}

fn is_valid_secp256k1_scalar(key: &[u8; 32]) -> bool {
    const SECP256K1_ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ];

    if key.iter().all(|&b| b == 0) {
        return false;
    }

    key < &SECP256K1_ORDER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex() {
        let hex = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a";
        let key = parse_private_key(hex).unwrap();
        assert_eq!(key[0], 0xc4);
        assert_eq!(key[31], 0x8a);
    }

    #[test]
    fn test_parse_hex_with_prefix() {
        let hex = "0xc4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a";
        let key = parse_private_key(hex).unwrap();
        assert_eq!(key[0], 0xc4);
    }

    #[test]
    fn test_parse_short_hex_5_bits() {
        let key = parse_private_key("0x15").unwrap();
        assert_eq!(key[31], 0x15);
        assert_eq!(key[30], 0x00);
        assert_eq!(key[0], 0x00);
    }

    #[test]
    fn test_parse_short_hex_10_bits() {
        let key = parse_private_key("0x202").unwrap();
        assert_eq!(key[31], 0x02);
        assert_eq!(key[30], 0x02);
    }

    #[test]
    fn test_parse_short_hex_20_bits() {
        let key = parse_private_key("0xd2c55").unwrap();
        assert_eq!(key[31], 0x55);
        assert_eq!(key[30], 0x2c);
        assert_eq!(key[29], 0x0d);
    }

    #[test]
    fn test_parse_short_hex_without_prefix() {
        let key = parse_private_key("0x1f").unwrap();
        assert_eq!(key[31], 0x1f);
    }

    #[test]
    fn test_parse_wif_uncompressed() {
        let wif = "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS";
        let key = parse_private_key(wif).unwrap();
        assert_eq!(key[0], 0xc4);
    }

    #[test]
    fn test_parse_wif_compressed() {
        let wif = "L3p8oAcQTtuokSCRHQ7i4MhjWc9zornvpJLfmg62sYpLRJF9woSu";
        let key = parse_private_key(wif).unwrap();
        assert_eq!(key[0], 0xc4);
    }

    #[test]
    fn test_parse_decimal() {
        let decimal = "1";
        let key = parse_private_key(decimal).unwrap();
        assert_eq!(key[31], 1);
        assert_eq!(key[0], 0);
    }

    #[test]
    fn test_parse_decimal_large() {
        let decimal = "115792089237316195423570985008687907852837564279074904382605163141518161494336";
        let key = parse_private_key(decimal).unwrap();
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn test_parse_decimal_out_of_range() {
        let decimal = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
        assert!(parse_private_key(decimal).is_err());
    }

    #[test]
    fn test_parse_invalid() {
        assert!(parse_private_key("not a key").is_err());
        assert!(parse_private_key("").is_err());
        assert!(parse_private_key("zzzz").is_err());
    }
}
