//! Electrum pre-BIP39 deterministic wallet derivation.
//!
//! Electrum 1.x (2011-2014) used a custom deterministic scheme before BIP39/BIP32:
//!
//! 1. **Seed stretching**: 100,000 SHA256 iterations
//! 2. **Master key**: stretched seed as private key scalar
//! 3. **Master public key**: uncompressed EC point (65 bytes)
//! 4. **Child sequence**: double SHA256 of `"{index}:{for_change}:" + mpk_bytes`
//! 5. **Child key**: `(master_privkey + sequence) mod n`
//!
//! Reference: <https://github.com/spesmilo/electrum/blob/b9196260cfd515363a026c3bfc7bc7aa757965a0/lib/bitcoin.py>

use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// Error types for Electrum derivation operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElectrumError {
    /// Invalid seed format
    InvalidSeed(String),
    /// Key derivation failed
    DerivationFailed(String),
}

impl std::fmt::Display for ElectrumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ElectrumError::InvalidSeed(msg) => write!(f, "Invalid seed: {}", msg),
            ElectrumError::DerivationFailed(msg) => write!(f, "Derivation failed: {}", msg),
        }
    }
}

impl std::error::Error for ElectrumError {}

#[derive(Clone)]
pub struct ElectrumDeriver {
    master_privkey: SecretKey,
    master_pubkey_bytes: [u8; 64],
    for_change: bool,
}

impl ElectrumDeriver {
    /// Create a deriver from a hex seed string.
    ///
    /// The seed should be a hex string (e.g., "0bbe2537d7527f2d7376d4bb9de8ac42...").
    /// This matches Electrum's behavior where the seed is treated as ASCII hex.
    ///
    /// # Example
    /// ```
    /// use vuke::electrum::ElectrumDeriver;
    ///
    /// let deriver = ElectrumDeriver::from_hex_seed(
    ///     "0bbe2537d7527f2d7376d4bb9de8ac42ca202dbae310471b88f2cbb0492e6e73"
    /// ).unwrap();
    /// ```
    pub fn from_hex_seed(hex_seed: &str) -> Result<Self, ElectrumError> {
        // Validate hex
        if !hex_seed.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ElectrumError::InvalidSeed("Seed must be valid hex".to_string()));
        }

        // Stretch key: seed is treated as ASCII-encoded hex string
        let stretched = stretch_key(hex_seed.as_bytes());

        Self::from_stretched_key(stretched)
    }

    /// Create a deriver from raw seed bytes.
    ///
    /// For Electrum compatibility, the bytes are hex-encoded first, then
    /// treated as ASCII for stretching. This matches Electrum's behavior
    /// where the mnemonic generates a hex string.
    pub fn from_seed_bytes(seed: &[u8]) -> Result<Self, ElectrumError> {
        let hex_seed = hex::encode(seed);
        Self::from_hex_seed(&hex_seed)
    }

    /// Create a deriver from an already-stretched key.
    fn from_stretched_key(stretched: [u8; 32]) -> Result<Self, ElectrumError> {
        let secp = Secp256k1::new();

        let master_privkey = SecretKey::from_slice(&stretched)
            .map_err(|e| ElectrumError::DerivationFailed(format!("Invalid stretched key: {}", e)))?;

        let master_pubkey = PublicKey::from_secret_key(&secp, &master_privkey);
        let pubkey_uncompressed = master_pubkey.serialize_uncompressed();

        // Extract 64 bytes (without 0x04 prefix)
        let mut master_pubkey_bytes = [0u8; 64];
        master_pubkey_bytes.copy_from_slice(&pubkey_uncompressed[1..65]);

        Ok(Self {
            master_privkey,
            master_pubkey_bytes,
            for_change: false,
        })
    }

    /// Set to derive change addresses (internal chain).
    pub fn with_change(mut self) -> Self {
        self.for_change = true;
        self
    }

    /// Get the master public key as hex string (without 0x04 prefix).
    pub fn master_pubkey_hex(&self) -> String {
        hex::encode(self.master_pubkey_bytes)
    }

    /// Derive a private key at the given index.
    ///
    /// # Arguments
    /// * `index` - Address index (0, 1, 2, ...)
    ///
    /// # Returns
    /// 32-byte private key
    pub fn derive_key(&self, index: u32) -> Result<[u8; 32], ElectrumError> {
        let for_change = if self.for_change { 1 } else { 0 };
        let sequence = get_sequence(&self.master_pubkey_bytes, for_change, index);

        // child_key = (master_privkey + sequence) mod n
        let scalar = Scalar::from_be_bytes(sequence)
            .map_err(|_| ElectrumError::DerivationFailed("Sequence overflow".to_string()))?;

        let child_key = self.master_privkey.add_tweak(&scalar)
            .map_err(|e| ElectrumError::DerivationFailed(format!("Key addition failed: {}", e)))?;

        Ok(child_key.secret_bytes())
    }

    /// Derive multiple keys starting from index 0.
    pub fn derive_keys(&self, count: u32) -> Result<Vec<[u8; 32]>, ElectrumError> {
        (0..count).map(|i| self.derive_key(i)).collect()
    }
}

/// Stretch a seed using 100,000 SHA256 iterations.
///
/// This is Electrum's key stretching algorithm:
/// ```text
/// x = seed
/// for i in 0..100000:
///     x = SHA256(x + seed)
/// return x
/// ```
///
/// # Arguments
/// * `seed` - Seed bytes (typically ASCII-encoded hex string)
pub fn stretch_key(seed: &[u8]) -> [u8; 32] {
    let mut x = seed.to_vec();

    for _ in 0..100_000 {
        let mut hasher = Sha256::new();
        hasher.update(&x);
        hasher.update(seed);
        x = hasher.finalize().to_vec();
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&x);
    result
}

/// Calculate the sequence number for child key derivation.
///
/// Uses double SHA256: `SHA256(SHA256("{index}:{for_change}:" + mpk_bytes))`
///
/// # Arguments
/// * `mpk` - Master public key bytes (64 bytes, without 0x04 prefix)
/// * `for_change` - 0 for receiving addresses, 1 for change addresses
/// * `index` - Address index
pub fn get_sequence(mpk: &[u8; 64], for_change: u8, index: u32) -> [u8; 32] {
    let prefix = format!("{}:{}:", index, for_change);

    let mut data = prefix.into_bytes();
    data.extend_from_slice(mpk);

    double_sha256(&data)
}

/// Double SHA256 hash.
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);

    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Truncate a seed for display (show first 8 and last 8 chars).
pub fn truncate_seed(seed: &str) -> String {
    if seed.len() <= 20 {
        seed.to_string()
    } else {
        format!("{}...{}", &seed[..8], &seed[seed.len()-8..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector from Electrum tests (official):
    // https://github.com/spesmilo/electrum/blob/ca410beae12d7af4e4b2f3f9541f47f17e32cb2d/tests/test_wallet_vertical.py#L176-L198
    const ELECTRUM_TEST_SEED_HEX: &str = "acb740e454c3134901d7c8f16497cc1c";
    const ELECTRUM_TEST_MPK: &str = "e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3";
    const ELECTRUM_TEST_RECEIVING_0: &str = "1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo";
    const ELECTRUM_TEST_CHANGE_0: &str = "1KRW8pH6HFHZh889VDq6fEKvmrsmApwNfe";

    #[test]
    fn test_stretch_key_deterministic() {
        let seed = b"test_seed";
        let result1 = stretch_key(seed);
        let result2 = stretch_key(seed);
        assert_eq!(result1, result2, "stretch_key should be deterministic");
    }

    #[test]
    fn test_stretch_key_different_seeds() {
        let result1 = stretch_key(b"seed1");
        let result2 = stretch_key(b"seed2");
        assert_ne!(result1, result2, "Different seeds should produce different results");
    }

    #[test]
    fn test_double_sha256() {
        let empty_double = double_sha256(b"");
        assert_eq!(
            hex::encode(empty_double),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn test_get_sequence_format() {
        let mpk = [0u8; 64];
        let seq0 = get_sequence(&mpk, 0, 0);
        let seq1 = get_sequence(&mpk, 0, 1);
        let seq_change = get_sequence(&mpk, 1, 0);

        assert_ne!(seq0, seq1);
        assert_ne!(seq0, seq_change);
    }

    #[test]
    fn test_deriver_master_pubkey_electrum() {
        let deriver = ElectrumDeriver::from_hex_seed(ELECTRUM_TEST_SEED_HEX).unwrap();
        assert_eq!(
            deriver.master_pubkey_hex().to_lowercase(),
            ELECTRUM_TEST_MPK.to_lowercase(),
        );
    }

    #[test]
    fn test_derive_receiving_address_electrum() {
        let deriver = ElectrumDeriver::from_hex_seed(ELECTRUM_TEST_SEED_HEX).unwrap();
        let key = deriver.derive_key(0).unwrap();

        let address = key_to_p2pkh_address_uncompressed(&key);
        assert_eq!(address, ELECTRUM_TEST_RECEIVING_0);
    }

    #[test]
    fn test_derive_change_address_electrum() {
        let deriver = ElectrumDeriver::from_hex_seed(ELECTRUM_TEST_SEED_HEX)
            .unwrap()
            .with_change();
        let key = deriver.derive_key(0).unwrap();

        let address = key_to_p2pkh_address_uncompressed(&key);
        assert_eq!(address, ELECTRUM_TEST_CHANGE_0);
    }

    #[test]
    fn test_derive_keys_multiple() {
        let deriver = ElectrumDeriver::from_hex_seed(ELECTRUM_TEST_SEED_HEX).unwrap();
        let keys = deriver.derive_keys(5).unwrap();

        assert_eq!(keys.len(), 5);

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "Keys at {} and {} should differ", i, j);
            }
        }
    }

    #[test]
    fn test_invalid_seed() {
        let result = ElectrumDeriver::from_hex_seed("not_valid_hex!");
        assert!(result.is_err());
    }

    #[test]
    fn test_truncate_seed() {
        let short = "abcd1234";
        assert_eq!(truncate_seed(short), "abcd1234");

        let long = "0bbe2537d7527f2d7376d4bb9de8ac42ca202dbae310471b88f2cbb0492e6e73";
        assert_eq!(truncate_seed(long), "0bbe2537...492e6e73");
    }

    fn key_to_p2pkh_address_uncompressed(key: &[u8; 32]) -> String {
        use bitcoin::key::Secp256k1;
        use bitcoin::network::Network;
        use bitcoin::secp256k1::SecretKey;
        use bitcoin::{Address, PrivateKey, PublicKey};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(key).expect("valid key");
        let mut priv_key = PrivateKey::new(secret, Network::Bitcoin);
        priv_key.compressed = false;
        let pub_key = PublicKey::from_private_key(&secp, &priv_key);

        Address::p2pkh(&pub_key, Network::Bitcoin).to_string()
    }
}
