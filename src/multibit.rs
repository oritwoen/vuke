//! MultiBit HD seed-as-entropy bug reproduction.
//!
//! MultiBit HD Beta 7 (pre-March 2015) had a critical bug where the 64-byte BIP39 seed
//! was incorrectly passed to BitcoinJ's `DeterministicSeed` constructor as if it were
//! entropy (expected 16-32 bytes), instead of using it as the master seed.
//!
//! Reference: https://github.com/Multibit-Legacy/multibit-hd/issues/445
//!
//! Normal BIP39/BIP32 flow:
//!   mnemonic → PBKDF2 → 64-byte seed → HMAC-SHA512("Bitcoin seed") → master key
//!
//! MultiBit HD bug:
//!   mnemonic → PBKDF2 → 64-byte seed → [TREATED AS ENTROPY] →
//!   → 48-word mnemonic → PBKDF2 → NEW 64-byte seed → HMAC-SHA512 → master key

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use std::sync::LazyLock;

type HmacSha512 = Hmac<Sha512>;

/// BIP39 English wordlist (2048 words), loaded at compile time.
static BIP39_WORDLIST: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("data/bip39_english.txt")
        .lines()
        .collect()
});

/// Error types for MultiBit HD operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultibitError {
    /// Invalid mnemonic format or checksum
    InvalidMnemonic(String),
    /// Wrong number of words (must be 12, 15, 18, 21, or 24)
    InvalidWordCount(usize),
    /// Word not found in BIP39 wordlist
    UnknownWord(String),
    /// BIP32 key derivation failed
    DerivationFailed(String),
}

impl std::fmt::Display for MultibitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultibitError::InvalidMnemonic(msg) => write!(f, "Invalid mnemonic: {}", msg),
            MultibitError::InvalidWordCount(n) => {
                write!(f, "Invalid word count: {} (expected 12, 15, 18, 21, or 24)", n)
            }
            MultibitError::UnknownWord(word) => write!(f, "Unknown BIP39 word: {}", word),
            MultibitError::DerivationFailed(msg) => write!(f, "Derivation failed: {}", msg),
        }
    }
}

impl std::error::Error for MultibitError {}

/// Reproduces the MultiBit HD Beta 7 seed-as-entropy bug.
///
/// This deriver takes a standard BIP39 mnemonic and produces the keys that
/// MultiBit HD would have generated due to its bug.
#[derive(Clone)]
pub struct MultibitBugDeriver {
    /// The "buggy" seed that MultiBit HD actually used for derivation
    buggy_seed: [u8; 64],
    /// BIP32 master private key (Il from HMAC-SHA512)
    master_key: [u8; 32],
    /// BIP32 master chain code (Ir from HMAC-SHA512)
    chain_code: [u8; 32],
}

impl MultibitBugDeriver {
    /// Create a deriver from a BIP39 mnemonic, reproducing the MultiBit HD bug.
    ///
    /// # Arguments
    /// * `mnemonic` - Space-separated BIP39 mnemonic words (12, 15, 18, 21, or 24 words)
    /// * `passphrase` - Optional BIP39 passphrase (empty string if none)
    ///
    /// # Example
    /// ```
    /// use vuke::multibit::MultibitBugDeriver;
    /// 
    /// let deriver = MultibitBugDeriver::from_mnemonic(
    ///     "skin join dog sponsor camera puppy ritual diagram arrow poverty boy elbow",
    ///     ""
    /// ).unwrap();
    /// ```
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, MultibitError> {
        // Validate and normalize mnemonic
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        validate_mnemonic(&words)?;

        // Step 1: mnemonic → BIP39 seed (64 bytes) - this is standard
        let original_seed = mnemonic_to_seed(mnemonic, passphrase);

        // Step 2: THE BUG - treat 64-byte seed as entropy → 48-word mnemonic
        let buggy_mnemonic = entropy_to_mnemonic(&original_seed);

        // Step 3: 48-word mnemonic → new BIP39 seed (this is what MultiBit HD actually used)
        let buggy_mnemonic_str = buggy_mnemonic.join(" ");
        let buggy_seed = mnemonic_to_seed(&buggy_mnemonic_str, passphrase);

        // Step 4: seed → BIP32 master key
        let (master_key, chain_code) = seed_to_master_key(&buggy_seed);

        Ok(Self {
            buggy_seed,
            master_key,
            chain_code,
        })
    }

    /// Get the "buggy" seed that MultiBit HD actually used.
    pub fn buggy_seed(&self) -> &[u8; 64] {
        &self.buggy_seed
    }

    /// Derive a private key at the MultiBit HD path: m/0'/0/index
    ///
    /// MultiBit HD used:
    /// - m/0' (hardened account 0)
    /// - m/0'/0 (external/receiving chain)
    /// - m/0'/0/i (address at index i)
    pub fn derive_key(&self, index: u32) -> Result<[u8; 32], MultibitError> {
        // m/0' (hardened)
        let (key_0h, chain_0h) = derive_hardened_child(&self.master_key, &self.chain_code, 0)?;
        
        // m/0'/0 (normal)
        let (key_0h_0, chain_0h_0) = derive_normal_child(&key_0h, &chain_0h, 0)?;
        
        // m/0'/0/index (normal)
        let (key_final, _) = derive_normal_child(&key_0h_0, &chain_0h_0, index)?;
        
        Ok(key_final)
    }

    /// Derive multiple keys starting from index 0.
    pub fn derive_keys(&self, count: u32) -> Result<Vec<[u8; 32]>, MultibitError> {
        (0..count).map(|i| self.derive_key(i)).collect()
    }
}

/// Validate mnemonic words.
fn validate_mnemonic(words: &[&str]) -> Result<(), MultibitError> {
    let valid_counts = [12, 15, 18, 21, 24];
    if !valid_counts.contains(&words.len()) {
        return Err(MultibitError::InvalidWordCount(words.len()));
    }

    for word in words {
        if !BIP39_WORDLIST.contains(word) {
            return Err(MultibitError::UnknownWord(word.to_string()));
        }
    }

    // Note: We don't validate checksum here because we want to support
    // potentially malformed mnemonics for research purposes.
    // The bug reproduction works regardless of checksum validity.

    Ok(())
}

/// Convert mnemonic to 64-byte seed using PBKDF2-HMAC-SHA512.
///
/// This is standard BIP39: PBKDF2(password=mnemonic, salt="mnemonic"+passphrase, iterations=2048)
fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let salt = format!("mnemonic{}", passphrase);
    pbkdf2_hmac_sha512(mnemonic.as_bytes(), salt.as_bytes(), 2048)
}

/// PBKDF2-HMAC-SHA512 implementation.
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    let mut result = [0u8; 64];
    
    // For 64-byte output with SHA512 (64-byte blocks), we only need one block
    // dkLen = 64, hLen = 64, so l = ceil(64/64) = 1
    
    // U1 = PRF(Password, Salt || INT(1))
    let mut salt_with_index = salt.to_vec();
    salt_with_index.extend_from_slice(&1u32.to_be_bytes());
    
    let mut mac = HmacSha512::new_from_slice(password).expect("HMAC accepts any key length");
    mac.update(&salt_with_index);
    let mut u = mac.finalize().into_bytes();
    
    result.copy_from_slice(&u);
    
    // U2 through U_iterations
    for _ in 1..iterations {
        let mut mac = HmacSha512::new_from_slice(password).expect("HMAC accepts any key length");
        mac.update(&u);
        u = mac.finalize().into_bytes();
        
        // XOR into result
        for (r, ui) in result.iter_mut().zip(u.iter()) {
            *r ^= ui;
        }
    }
    
    result
}

/// Convert entropy bytes to BIP39 mnemonic words.
///
/// This handles arbitrary entropy lengths (including 64 bytes for the bug).
/// For 64 bytes (512 bits), produces a 48-word mnemonic.
fn entropy_to_mnemonic(entropy: &[u8]) -> Vec<String> {
    // Calculate checksum: first (entropy_bits / 32) bits of SHA256(entropy)
    let hash = Sha256::digest(entropy);
    let checksum_bits = entropy.len() * 8 / 32;
    
    // Convert entropy to bits
    let mut bits: Vec<bool> = Vec::with_capacity(entropy.len() * 8 + checksum_bits);
    for byte in entropy {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    
    // Append checksum bits
    for i in 0..checksum_bits {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        bits.push((hash[byte_idx] >> bit_idx) & 1 == 1);
    }
    
    // Convert to 11-bit indices and look up words
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

/// Convert 64-byte seed to BIP32 master key using HMAC-SHA512.
///
/// Returns (master_private_key, chain_code).
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

/// BIP32 hardened child derivation.
///
/// For hardened derivation (index >= 2^31), we use:
/// HMAC-SHA512(key=chain_code, data=0x00 || parent_key || index)
fn derive_hardened_child(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32]), MultibitError> {
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
    
    // child_key = (il + parent_key) mod n
    let child_key = scalar_add(il, parent_key)?;
    
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(ir);
    
    Ok((child_key, chain_code))
}

/// BIP32 normal (non-hardened) child derivation.
///
/// For normal derivation (index < 2^31), we use:
/// HMAC-SHA512(key=chain_code, data=parent_pubkey || index)
fn derive_normal_child(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32]), MultibitError> {
    // Get compressed public key from private key
    let pubkey = private_to_public(parent_key)?;
    
    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&pubkey);
    data.extend_from_slice(&index.to_be_bytes());
    
    let mut mac = HmacSha512::new_from_slice(parent_chain_code).expect("HMAC key");
    mac.update(&data);
    let result = mac.finalize().into_bytes();
    
    let il = &result[0..32];
    let ir = &result[32..64];
    
    // child_key = (il + parent_key) mod n
    let child_key = scalar_add(il, parent_key)?;
    
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(ir);
    
    Ok((child_key, chain_code))
}

/// Derive compressed public key from private key.
fn private_to_public(private_key: &[u8; 32]) -> Result<[u8; 33], MultibitError> {
    use secp256k1::{Secp256k1, SecretKey};
    
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(private_key)
        .map_err(|e| MultibitError::DerivationFailed(format!("Invalid private key: {}", e)))?;
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    
    Ok(pubkey.serialize())
}

/// Add two scalars modulo the secp256k1 curve order.
fn scalar_add(a: &[u8], b: &[u8; 32]) -> Result<[u8; 32], MultibitError> {
    use secp256k1::{Scalar, SecretKey};
    
    let secret_b = SecretKey::from_slice(b)
        .map_err(|e| MultibitError::DerivationFailed(format!("Invalid key b: {}", e)))?;
    
    let scalar_a_bytes: [u8; 32] = a.try_into()
        .map_err(|_| MultibitError::DerivationFailed("Invalid scalar length".to_string()))?;
    
    let scalar_a = Scalar::from_be_bytes(scalar_a_bytes)
        .map_err(|_| MultibitError::DerivationFailed("Scalar overflow".to_string()))?;
    
    let result = secret_b.add_tweak(&scalar_a)
        .map_err(|e| MultibitError::DerivationFailed(format!("Scalar addition failed: {}", e)))?;
    
    Ok(result.secret_bytes())
}

/// Truncate a mnemonic for display (show first 2 and last 2 words).
pub fn truncate_mnemonic(mnemonic: &str) -> String {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if words.len() <= 4 {
        mnemonic.to_string()
    } else {
        format!("{}...{}", words[..2].join(" "), words[words.len()-2..].join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip39_wordlist_loaded() {
        assert_eq!(BIP39_WORDLIST.len(), 2048);
        assert_eq!(BIP39_WORDLIST[0], "abandon");
        assert_eq!(BIP39_WORDLIST[2047], "zoo");
    }

    #[test]
    fn test_pbkdf2_hmac_sha512() {
        // Test vector from BIP39 reference
        let password = b"password";
        let salt = b"salt";
        let result = pbkdf2_hmac_sha512(password, salt, 1);
        
        // First iteration should be just HMAC-SHA512(password, salt || 0x00000001)
        // This is a sanity check, not a full test vector
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_entropy_to_mnemonic_standard() {
        // 16 bytes (128 bits) → 12 words
        let entropy = [0u8; 16];
        let words = entropy_to_mnemonic(&entropy);
        assert_eq!(words.len(), 12);
        // All zeros + checksum should give specific words
        assert_eq!(words[0], "abandon");
    }

    #[test]
    fn test_entropy_to_mnemonic_64_bytes() {
        // 64 bytes (512 bits) → 48 words (the bug scenario)
        let entropy = [0u8; 64];
        let words = entropy_to_mnemonic(&entropy);
        assert_eq!(words.len(), 48);
    }

    #[test]
    fn test_multibit_bug_issue_445() {
        // Test vector from https://github.com/Multibit-Legacy/multibit-hd/issues/445
        let mnemonic = "skin join dog sponsor camera puppy ritual diagram arrow poverty boy elbow";
        
        let deriver = MultibitBugDeriver::from_mnemonic(mnemonic, "").unwrap();
        
        // Derive first key at m/0'/0/0
        let key = deriver.derive_key(0).unwrap();
        
        // Convert to address and verify
        let address = key_to_p2pkh_address(&key);
        assert_eq!(address, "1LQ8XnNKqC7Vu7atH5k4X8qVCc9ug2q7WE", 
            "First address should match MultiBit HD buggy output");
    }

    #[test]
    fn test_validate_mnemonic_valid() {
        let words: Vec<&str> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split_whitespace().collect();
        assert!(validate_mnemonic(&words).is_ok());
    }

    #[test]
    fn test_validate_mnemonic_invalid_count() {
        let words: Vec<&str> = "abandon abandon abandon".split_whitespace().collect();
        assert!(matches!(
            validate_mnemonic(&words),
            Err(MultibitError::InvalidWordCount(3))
        ));
    }

    #[test]
    fn test_validate_mnemonic_unknown_word() {
        let words: Vec<&str> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword"
            .split_whitespace().collect();
        assert!(matches!(
            validate_mnemonic(&words),
            Err(MultibitError::UnknownWord(_))
        ));
    }

    /// Helper to convert private key to P2PKH address (for testing)
    fn key_to_p2pkh_address(key: &[u8; 32]) -> String {
        use bitcoin::key::Secp256k1;
        use bitcoin::network::Network;
        use bitcoin::secp256k1::SecretKey;
        use bitcoin::{Address, PrivateKey, PublicKey};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(key).expect("valid key");
        let mut priv_key = PrivateKey::new(secret, Network::Bitcoin);
        priv_key.compressed = true;
        let pub_key = PublicKey::from_private_key(&secp, &priv_key);
        
        Address::p2pkh(&pub_key, Network::Bitcoin).to_string()
    }

    #[test]
    fn test_buggy_mnemonic_generation() {
        // From issue #445, the buggy 48-word mnemonic should be:
        // "trim snack gorilla discover coast hat member pig build snake mention balance 
        //  acoustic neutral asthma swift oven choice human orange smart intact soup wild 
        //  nice public assume lady wing snake critic enrich say session useful base 
        //  echo nut emotion fantasy trumpet dog deer basket expand hand surface coach"
        
        let mnemonic = "skin join dog sponsor camera puppy ritual diagram arrow poverty boy elbow";
        let original_seed = mnemonic_to_seed(mnemonic, "");
        let buggy_mnemonic = entropy_to_mnemonic(&original_seed);
        
        assert_eq!(buggy_mnemonic.len(), 48);
        assert_eq!(buggy_mnemonic[0], "trim");
        assert_eq!(buggy_mnemonic[1], "snack");
        assert_eq!(buggy_mnemonic[2], "gorilla");
        // ... more words could be verified
        assert_eq!(buggy_mnemonic[47], "coach");
    }
}
