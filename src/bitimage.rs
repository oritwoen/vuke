//! Bitimage key derivation - file to Bitcoin key.
//!
//! Implements the Bitimage method: file → base64 → SHA256 → BIP39 mnemonic → HD key

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use std::sync::LazyLock;

type HmacSha512 = Hmac<Sha512>;

static BIP39_WORDLIST: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| include_str!("data/bip39_english.txt").lines().collect());

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitimageError {
    InvalidPath(String),
    DerivationFailed(String),
}

impl std::fmt::Display for BitimageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitimageError::InvalidPath(msg) => write!(f, "Invalid derivation path: {}", msg),
            BitimageError::DerivationFailed(msg) => write!(f, "Derivation failed: {}", msg),
        }
    }
}

impl std::error::Error for BitimageError {}

pub struct BitimageDeriver {
    master_key: [u8; 32],
    chain_code: [u8; 32],
}

impl BitimageDeriver {
    pub fn from_file_bytes(data: &[u8], passphrase: &str) -> Self {
        let base64_encoded = BASE64.encode(data);
        let hash = Sha256::digest(base64_encoded.as_bytes());

        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&hash);

        let mnemonic = entropy_to_mnemonic(&entropy);
        let mnemonic_str = mnemonic.join(" ");
        let seed = mnemonic_to_seed(&mnemonic_str, passphrase);
        let (master_key, chain_code) = seed_to_master_key(&seed);

        Self {
            master_key,
            chain_code,
        }
    }

    pub fn derive_path(&self, path: &str) -> Result<[u8; 32], BitimageError> {
        let components = parse_derivation_path(path)?;

        let mut key = self.master_key;
        let mut chain = self.chain_code;

        for (index, hardened) in components {
            let (new_key, new_chain) = if hardened {
                derive_hardened_child(&key, &chain, index)?
            } else {
                derive_normal_child(&key, &chain, index)?
            };
            key = new_key;
            chain = new_chain;
        }

        Ok(key)
    }
}

fn parse_derivation_path(path: &str) -> Result<Vec<(u32, bool)>, BitimageError> {
    let path = path.trim();
    if !path.starts_with("m/") && path != "m" {
        return Err(BitimageError::InvalidPath(
            "Path must start with 'm/' or be 'm'".to_string(),
        ));
    }

    if path == "m" {
        return Ok(vec![]);
    }

    let components = path[2..].split('/');
    let mut result = Vec::new();

    for component in components {
        if component.is_empty() {
            continue;
        }

        let (index_str, hardened) = if component.ends_with('\'') || component.ends_with('h') {
            (&component[..component.len() - 1], true)
        } else {
            (component, false)
        };

        let index: u32 = index_str
            .parse()
            .map_err(|_| BitimageError::InvalidPath(format!("Invalid index: {}", component)))?;

        result.push((index, hardened));
    }

    Ok(result)
}

fn entropy_to_mnemonic(entropy: &[u8]) -> Vec<String> {
    let hash = Sha256::digest(entropy);
    let checksum_bits = entropy.len() * 8 / 32;

    let mut bits: Vec<bool> = Vec::with_capacity(entropy.len() * 8 + checksum_bits);
    for byte in entropy {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }

    for i in 0..checksum_bits {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        bits.push((hash[byte_idx] >> bit_idx) & 1 == 1);
    }

    let num_words = bits.len() / 11;
    let mut words = Vec::with_capacity(num_words);

    for i in 0..num_words {
        let mut index: usize = 0;
        for j in 0..11 {
            index = (index << 1) | (bits[i * 11 + j] as usize);
        }
        words.push(BIP39_WORDLIST[index].to_string());
    }

    words
}

fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let salt = format!("mnemonic{}", passphrase);
    pbkdf2_hmac_sha512(mnemonic.as_bytes(), salt.as_bytes(), 2048)
}

fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    let mut result = [0u8; 64];

    let mut salt_with_index = salt.to_vec();
    salt_with_index.extend_from_slice(&1u32.to_be_bytes());

    let mut mac = HmacSha512::new_from_slice(password).expect("HMAC accepts any key length");
    mac.update(&salt_with_index);
    let mut u = mac.finalize().into_bytes();

    result.copy_from_slice(&u);

    for _ in 1..iterations {
        let mut mac = HmacSha512::new_from_slice(password).expect("HMAC accepts any key length");
        mac.update(&u);
        u = mac.finalize().into_bytes();

        for (r, ui) in result.iter_mut().zip(u.iter()) {
            *r ^= ui;
        }
    }

    result
}

fn seed_to_master_key(seed: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC key");
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut master_key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    master_key.copy_from_slice(&result[0..32]);
    chain_code.copy_from_slice(&result[32..64]);

    (master_key, chain_code)
}

fn derive_hardened_child(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32]), BitimageError> {
    let hardened_index = index | 0x80000000;

    let mut data = Vec::with_capacity(37);
    data.push(0x00);
    data.extend_from_slice(parent_key);
    data.extend_from_slice(&hardened_index.to_be_bytes());

    let mut mac = HmacSha512::new_from_slice(parent_chain_code).expect("HMAC key");
    mac.update(&data);
    let result = mac.finalize().into_bytes();

    let il = &result[0..32];
    let ir = &result[32..64];

    let child_key = scalar_add(il, parent_key)?;

    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(ir);

    Ok((child_key, chain_code))
}

fn derive_normal_child(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32]), BitimageError> {
    let pubkey = private_to_public(parent_key)?;

    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&pubkey);
    data.extend_from_slice(&index.to_be_bytes());

    let mut mac = HmacSha512::new_from_slice(parent_chain_code).expect("HMAC key");
    mac.update(&data);
    let result = mac.finalize().into_bytes();

    let il = &result[0..32];
    let ir = &result[32..64];

    let child_key = scalar_add(il, parent_key)?;

    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(ir);

    Ok((child_key, chain_code))
}

fn private_to_public(private_key: &[u8; 32]) -> Result<[u8; 33], BitimageError> {
    use secp256k1::{Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(private_key)
        .map_err(|e| BitimageError::DerivationFailed(format!("Invalid private key: {}", e)))?;
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);

    Ok(pubkey.serialize())
}

fn scalar_add(a: &[u8], b: &[u8; 32]) -> Result<[u8; 32], BitimageError> {
    use secp256k1::{Scalar, SecretKey};

    let secret_b = SecretKey::from_slice(b)
        .map_err(|e| BitimageError::DerivationFailed(format!("Invalid key b: {}", e)))?;

    let scalar_a_bytes: [u8; 32] = a
        .try_into()
        .map_err(|_| BitimageError::DerivationFailed("Invalid scalar length".to_string()))?;

    let scalar_a = Scalar::from_be_bytes(scalar_a_bytes)
        .map_err(|_| BitimageError::DerivationFailed("Scalar overflow".to_string()))?;

    let result = secret_b
        .add_tweak(&scalar_a)
        .map_err(|e| BitimageError::DerivationFailed(format!("Scalar addition failed: {}", e)))?;

    Ok(result.secret_bytes())
}

pub fn increment_path_index(path: &str) -> String {
    if let Some(last_slash) = path.rfind('/') {
        let prefix = &path[..=last_slash];
        let suffix = &path[last_slash + 1..];

        let (index_str, hardened_marker) = if suffix.ends_with('\'') || suffix.ends_with('h') {
            (&suffix[..suffix.len() - 1], &suffix[suffix.len() - 1..])
        } else {
            (suffix, "")
        };

        if let Ok(index) = index_str.parse::<u32>() {
            return format!("{}{}{}", prefix, index + 1, hardened_marker);
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_derivation_path_bip84() {
        let path = "m/84'/0'/0'/0/0";
        let components = parse_derivation_path(path).unwrap();
        assert_eq!(
            components,
            vec![(84, true), (0, true), (0, true), (0, false), (0, false),]
        );
    }

    #[test]
    fn test_parse_derivation_path_master_only() {
        let components = parse_derivation_path("m").unwrap();
        assert!(components.is_empty());
    }

    #[test]
    fn test_parse_derivation_path_invalid() {
        assert!(parse_derivation_path("84'/0'/0'/0/0").is_err());
        assert!(parse_derivation_path("m/abc").is_err());
    }

    #[test]
    fn test_increment_path_index() {
        assert_eq!(increment_path_index("m/84'/0'/0'/0/0"), "m/84'/0'/0'/0/1");
        assert_eq!(increment_path_index("m/84'/0'/0'/0/5"), "m/84'/0'/0'/0/6");
        assert_eq!(increment_path_index("m/44'/0'/0'/0'"), "m/44'/0'/0'/1'");
    }

    #[test]
    fn test_bitimage_deterministic() {
        let data = b"hello world";
        let deriver = BitimageDeriver::from_file_bytes(data, "");
        let key1 = deriver.derive_path("m/84'/0'/0'/0/0").unwrap();

        let deriver2 = BitimageDeriver::from_file_bytes(data, "");
        let key2 = deriver2.derive_path("m/84'/0'/0'/0/0").unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_bitimage_passphrase_changes_key() {
        let data = b"hello world";
        let key_no_pass = BitimageDeriver::from_file_bytes(data, "")
            .derive_path("m/84'/0'/0'/0/0")
            .unwrap();
        let key_with_pass = BitimageDeriver::from_file_bytes(data, "secret")
            .derive_path("m/84'/0'/0'/0/0")
            .unwrap();

        assert_ne!(key_no_pass, key_with_pass);
    }

    #[test]
    fn test_different_paths_different_keys() {
        let data = b"test";
        let deriver = BitimageDeriver::from_file_bytes(data, "");
        let key0 = deriver.derive_path("m/84'/0'/0'/0/0").unwrap();
        let key1 = deriver.derive_path("m/84'/0'/0'/0/1").unwrap();

        assert_ne!(key0, key1);
    }
}
