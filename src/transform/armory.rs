//! Armory HD wallet derivation transform.
//!
//! Simulates Armory deterministic wallet key generation.
//! Armory was an early Bitcoin wallet that used a custom HD derivation scheme
//! before BIP32 was standardized.

use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use super::{Input, Key, Transform};

type HmacSha256 = Hmac<Sha256>;

pub struct ArmoryTransform {
    secp: Secp256k1<secp256k1::All>,
}

impl ArmoryTransform {
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    /// Generate Armory-style derived key from seed
    fn generate_key(&self, seed: &[u8]) -> Option<Key> {
        // 1. Derive chaincode: HMAC-SHA256(key=SHA256(SHA256(root)), msg="Derive Chaincode from Root Key")
        let hash1 = Sha256::digest(seed);
        let hash2 = Sha256::digest(&hash1);

        let mut mac = HmacSha256::new_from_slice(&hash2).ok()?;
        mac.update(b"Derive Chaincode from Root Key");
        let chaincode_bytes = mac.finalize().into_bytes();
        let mut chaincode = [0u8; 32];
        chaincode.copy_from_slice(&chaincode_bytes);

        // 2. Get root private key
        let current_priv = if seed.len() == 32 {
            SecretKey::from_slice(seed).ok()?
        } else {
            SecretKey::from_slice(&hash1).ok()?
        };

        // 3. Advance to index 5 (P5) using Armory derivation
        let derived = self.advance_key(current_priv, &chaincode, 4)?;

        Some(derived.secret_bytes())
    }

    /// Advance key by n steps using Armory derivation
    fn advance_key(&self, mut key: SecretKey, chaincode: &[u8; 32], steps: usize) -> Option<SecretKey> {
        for _ in 0..steps {
            let pubkey = PublicKey::from_secret_key(&self.secp, &key);
            let pubkey_bytes = pubkey.serialize_uncompressed();

            let h1 = Sha256::digest(&pubkey_bytes);
            let h2 = Sha256::digest(&h1);

            let mut scalar_bytes = [0u8; 32];
            for i in 0..32 {
                scalar_bytes[i] = h2[i] ^ chaincode[i];
            }

            let scalar = Scalar::from_be_bytes(scalar_bytes).ok()?;
            key = key.mul_tweak(&scalar).ok()?;
        }
        Some(key)
    }
}

impl Default for ArmoryTransform {
    fn default() -> Self {
        Self::new()
    }
}

impl Transform for ArmoryTransform {
    fn name(&self) -> &'static str {
        "armory"
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        for input in inputs {
            // Try string hash as seed
            let hash = Sha256::digest(input.string_val.as_bytes());
            if let Some(key) = self.generate_key(&hash) {
                output.push((input.string_val.clone(), key));
            }

            // Try big-endian bytes if available
            if let Some(be) = input.bytes_be {
                let mut raw_seed = [0u8; 32];
                raw_seed[24..].copy_from_slice(&be);
                if let Some(key) = self.generate_key(&raw_seed) {
                    output.push((input.string_val.clone(), key));
                }
            }
        }
    }
}
