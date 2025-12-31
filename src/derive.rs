//! Key derivation - convert private key bytes to addresses.

use bitcoin::key::Secp256k1;
use bitcoin::network::Network;
use bitcoin::secp256k1::constants::CURVE_ORDER;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, CompressedPublicKey, PrivateKey, PublicKey};
use num_bigint::BigUint;

/// Derived key with all address formats.
#[derive(Debug, Clone)]
pub struct DerivedKey {
    /// Raw 32-byte private key
    pub raw: [u8; 32],
    /// Raw private key hex (64 chars)
    pub private_key_hex: String,
    /// Private key as decimal string (for puzzle analysis)
    pub private_key_decimal: String,
    /// Private key as binary string (256 chars of 0s and 1s)
    pub private_key_binary: String,
    /// Effective bit length (position of highest set bit)
    pub bit_length: u16,
    /// Hamming weight (number of 1-bits)
    pub hamming_weight: u16,
    /// Leading zeros count in hex representation
    pub leading_zeros: u8,
    /// Compressed public key hex (66 chars)
    pub pubkey_compressed: String,
    /// Uncompressed public key hex (130 chars)
    pub pubkey_uncompressed: String,
    /// WIF compressed (starts with K or L)
    pub wif_compressed: String,
    /// WIF uncompressed (starts with 5)
    pub wif_uncompressed: String,
    /// P2PKH address (compressed pubkey)
    pub p2pkh_compressed: String,
    /// P2PKH address (uncompressed pubkey)
    pub p2pkh_uncompressed: String,
    /// P2WPKH (bech32) address
    pub p2wpkh: String,
}

impl DerivedKey {
    /// Get all addresses as slice for matching.
    pub fn addresses(&self) -> [&str; 3] {
        [
            &self.p2pkh_compressed,
            &self.p2pkh_uncompressed,
            &self.p2wpkh,
        ]
    }
}

/// Key deriver - converts 32-byte keys to addresses.
pub struct KeyDeriver {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    network: Network,
}

impl KeyDeriver {
    /// Create new deriver for mainnet.
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
            network: Network::Bitcoin,
        }
    }

    /// Create deriver for specific network.
    pub fn with_network(network: Network) -> Self {
        Self {
            secp: Secp256k1::new(),
            network,
        }
    }

    /// Derive all key formats from raw 32-byte key.
    pub fn derive(&self, key: &[u8; 32]) -> DerivedKey {
        let secret_key = SecretKey::from_slice(key).unwrap_or_else(|_| {
            // Normalize invalid keys by reducing mod curve order.
            let mut int_val = BigUint::from_bytes_be(key);
            let order = BigUint::from_bytes_be(&CURVE_ORDER);
            int_val %= &order;
            if int_val == BigUint::from(0u8) {
                int_val = BigUint::from(1u8);
            }

            let mut normalized = [0u8; 32];
            let bytes = int_val.to_bytes_be();
            let start = 32 - bytes.len();
            normalized[start..].copy_from_slice(&bytes);
            SecretKey::from_slice(&normalized).expect("normalized key")
        });
        let key_bytes = secret_key.secret_bytes();

        // Public keys
        let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&self.secp, &secret_key);
        let pubkey_compressed = hex::encode(secp_pubkey.serialize());
        let pubkey_uncompressed = hex::encode(secp_pubkey.serialize_uncompressed());

        // WIF formats
        let mut priv_compressed = PrivateKey::new(secret_key, self.network);
        priv_compressed.compressed = true;
        let mut priv_uncompressed = PrivateKey::new(secret_key, self.network);
        priv_uncompressed.compressed = false;

        // Public key wrappers for address generation
        let pk_compressed = PublicKey::from_private_key(&self.secp, &priv_compressed);
        let pk_uncompressed = PublicKey::from_private_key(&self.secp, &priv_uncompressed);

        // P2PKH addresses
        let p2pkh_compressed = Address::p2pkh(&pk_compressed, self.network).to_string();
        let p2pkh_uncompressed = Address::p2pkh(&pk_uncompressed, self.network).to_string();

        // P2WPKH (requires compressed pubkey)
        let compressed_pk = CompressedPublicKey::from_slice(&secp_pubkey.serialize())
            .expect("valid compressed pubkey");
        let p2wpkh = Address::p2wpkh(&compressed_pk, self.network).to_string();

        // Decimal representation (big-endian)
        let private_key_decimal = BigUint::from_bytes_be(&key_bytes).to_string();

        // Binary representation (256 bits, big-endian)
        let private_key_binary: String = key_bytes
            .iter()
            .flat_map(|byte| {
                (0..8)
                    .rev()
                    .map(move |i| if byte & (1 << i) != 0 { '1' } else { '0' })
            })
            .collect();

        // Bit length: 256 - leading zero bits
        let leading_zero_bits: u16 = key_bytes.iter().take_while(|&&b| b == 0).count() as u16 * 8
            + key_bytes
                .iter()
                .find(|&&b| b != 0)
                .map(|b| b.leading_zeros() as u16)
                .unwrap_or(0);
        let bit_length = 256 - leading_zero_bits;

        // Hamming weight: count of 1-bits
        let hamming_weight: u16 = key_bytes.iter().map(|b| b.count_ones() as u16).sum();

        // Leading zeros in hex: count of '0' chars at start
        let hex_str = hex::encode(key_bytes);
        let leading_zeros = hex_str.chars().take_while(|&c| c == '0').count() as u8;

        DerivedKey {
            raw: key_bytes,
            private_key_hex: hex_str,
            private_key_decimal,
            private_key_binary,
            bit_length,
            hamming_weight,
            leading_zeros,
            pubkey_compressed,
            pubkey_uncompressed,
            wif_compressed: priv_compressed.to_wif(),
            wif_uncompressed: priv_uncompressed.to_wif(),
            p2pkh_compressed,
            p2pkh_uncompressed,
            p2wpkh,
        }
    }
}

impl Default for KeyDeriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_known_key() {
        // "correct horse battery staple" SHA256
        let key: [u8; 32] = [
            0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6,
            0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b,
            0xd4, 0xe3, 0x9a, 0x8a,
        ];

        let deriver = KeyDeriver::new();
        let derived = deriver.derive(&key);

        assert_eq!(
            derived.wif_uncompressed,
            "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS"
        );
        assert_eq!(
            derived.p2pkh_uncompressed,
            "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T"
        );
        assert!(derived.wif_compressed.starts_with('K') || derived.wif_compressed.starts_with('L'));
        assert!(derived.p2wpkh.starts_with("bc1q"));
    }

    #[test]
    fn test_addresses_returns_all() {
        let key = [1u8; 32];
        let deriver = KeyDeriver::new();
        let derived = deriver.derive(&key);

        let addrs = derived.addresses();
        assert_eq!(addrs.len(), 3);
        assert!(addrs[0].starts_with('1')); // P2PKH compressed
        assert!(addrs[1].starts_with('1')); // P2PKH uncompressed
        assert!(addrs[2].starts_with("bc1q")); // P2WPKH
    }

    #[test]
    fn test_derive_normalizes_zero_key() {
        // All-zero key is invalid on secp256k1; deriver should normalize.
        let key = [0u8; 32];
        let deriver = KeyDeriver::new();
        let derived = deriver.derive(&key);

        assert_eq!(derived.private_key_decimal, "1");
        assert_eq!(derived.bit_length, 1);
    }
}
