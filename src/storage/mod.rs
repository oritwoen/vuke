//! Persistent storage backends for generated keys.

mod parquet_backend;
mod schema;

pub use parquet_backend::ParquetBackend;
pub use schema::{fields, records_to_batch, result_schema};

use std::fmt;
use std::path::PathBuf;

use arrow::datatypes::Schema;

#[derive(Clone)]
pub struct PrivateKeyRecord<'a> {
    pub raw: &'a [u8; 32],
    pub hex: &'a str,
    pub decimal: &'a str,
    pub binary: &'a str,
    pub bit_length: u16,
    pub hamming_weight: u16,
    pub leading_zeros: u8,
}

impl std::fmt::Debug for PrivateKeyRecord<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKeyRecord")
            .field("raw", &"[REDACTED]")
            .field("hex", &"[REDACTED]")
            .field("decimal", &"[REDACTED]")
            .field("binary", &"[REDACTED]")
            .field("bit_length", &self.bit_length)
            .field("hamming_weight", &self.hamming_weight)
            .field("leading_zeros", &self.leading_zeros)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct PublicKeyRecord<'a> {
    pub format: &'a str,
    pub value: &'a str,
}

#[derive(Debug, Clone)]
pub struct AddressRecord<'a> {
    pub address_type: &'a str,
    pub address: &'a str,
}

#[derive(Debug, Clone)]
pub struct ExportFormatRecord<'a> {
    pub format: &'a str,
    pub value: &'a str,
}

#[derive(Debug, Clone)]
pub struct ResultRecord<'a> {
    pub source: &'a str,
    pub transform: &'a str,
    pub chain: &'a str,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub private_key: PrivateKeyRecord<'a>,
    pub public_keys: &'a [PublicKeyRecord<'a>],
    pub addresses: &'a [AddressRecord<'a>],
    pub export_formats: &'a [ExportFormatRecord<'a>],
    pub matched_target: Option<&'a str>,
}

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Parquet(::parquet::errors::ParquetError),
    Arrow(arrow::error::ArrowError),
    SchemaMismatch(String),
    NotInitialized,
    Other(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "IO error: {}", e),
            StorageError::Parquet(e) => write!(f, "Parquet error: {}", e),
            StorageError::Arrow(e) => write!(f, "Arrow error: {}", e),
            StorageError::SchemaMismatch(msg) => write!(f, "Schema mismatch: {}", msg),
            StorageError::NotInitialized => write!(f, "Storage backend not initialized"),
            StorageError::Other(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Io(e) => Some(e),
            StorageError::Parquet(e) => Some(e),
            StorageError::Arrow(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::Io(err)
    }
}

impl From<::parquet::errors::ParquetError> for StorageError {
    fn from(err: ::parquet::errors::ParquetError) -> Self {
        StorageError::Parquet(err)
    }
}

impl From<arrow::error::ArrowError> for StorageError {
    fn from(err: arrow::error::ArrowError) -> Self {
        StorageError::Arrow(err)
    }
}

pub type Result<T> = std::result::Result<T, StorageError>;

pub trait StorageBackend: Send + Sync {
    fn write_batch(&mut self, records: &[ResultRecord<'_>]) -> Result<()>;

    /// Returns all written file paths. For chunked backends, includes all chunks.
    fn flush(&mut self) -> Result<Vec<PathBuf>>;

    fn schema(&self) -> &Schema;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn private_key_record_creation() {
        let raw = [0xab_u8; 32];
        let record = PrivateKeyRecord {
            raw: &raw,
            hex: "abababab",
            decimal: "12345",
            binary: "10101011",
            bit_length: 256,
            hamming_weight: 128,
            leading_zeros: 0,
        };
        assert_eq!(record.raw[0], 0xab);
        assert_eq!(record.bit_length, 256);
    }

    #[test]
    fn public_key_record_creation() {
        let record = PublicKeyRecord {
            format: "compressed",
            value: "02abc123",
        };
        assert_eq!(record.format, "compressed");
    }

    #[test]
    fn address_record_creation() {
        let record = AddressRecord {
            address_type: "p2wpkh",
            address: "bc1qtest",
        };
        assert_eq!(record.address_type, "p2wpkh");
    }

    #[test]
    fn export_format_record_creation() {
        let record = ExportFormatRecord {
            format: "wif_compressed",
            value: "L1234",
        };
        assert_eq!(record.format, "wif_compressed");
    }

    #[test]
    fn result_record_creation() {
        let raw = [1_u8; 32];
        let private_key = PrivateKeyRecord {
            raw: &raw,
            hex: "0101",
            decimal: "1",
            binary: "00000001",
            bit_length: 1,
            hamming_weight: 1,
            leading_zeros: 62,
        };

        let public_keys = [
            PublicKeyRecord { format: "compressed", value: "02abc" },
            PublicKeyRecord { format: "uncompressed", value: "04abc" },
        ];

        let addresses = [
            AddressRecord { address_type: "p2pkh", address: "1abc" },
            AddressRecord { address_type: "p2wpkh", address: "bc1q" },
        ];

        let export_formats = [
            ExportFormatRecord { format: "wif_compressed", value: "L1" },
        ];

        let record = ResultRecord {
            source: "test_seed",
            transform: "sha256",
            chain: "bitcoin",
            timestamp: chrono::Utc::now(),
            private_key,
            public_keys: &public_keys,
            addresses: &addresses,
            export_formats: &export_formats,
            matched_target: Some("1abc"),
        };

        assert_eq!(record.source, "test_seed");
        assert_eq!(record.chain, "bitcoin");
        assert_eq!(record.public_keys.len(), 2);
        assert_eq!(record.addresses.len(), 2);
        assert!(record.matched_target.is_some());
    }

    #[test]
    fn result_record_empty_slices() {
        let raw = [0_u8; 32];
        let private_key = PrivateKeyRecord {
            raw: &raw,
            hex: "",
            decimal: "0",
            binary: "",
            bit_length: 0,
            hamming_weight: 0,
            leading_zeros: 64,
        };

        let record = ResultRecord {
            source: "",
            transform: "direct",
            chain: "ethereum",
            timestamp: chrono::Utc::now(),
            private_key,
            public_keys: &[],
            addresses: &[],
            export_formats: &[],
            matched_target: None,
        };

        assert!(record.public_keys.is_empty());
        assert!(record.addresses.is_empty());
        assert!(record.matched_target.is_none());
    }

    #[test]
    fn storage_error_display() {
        let err = StorageError::NotInitialized;
        assert!(err.to_string().contains("not initialized"));

        let err = StorageError::SchemaMismatch("test".to_string());
        assert!(err.to_string().contains("Schema mismatch"));
        assert!(err.to_string().contains("test"));

        let err = StorageError::Other("custom error".to_string());
        assert!(err.to_string().contains("custom error"));
    }

    #[test]
    fn storage_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let storage_err: StorageError = io_err.into();
        assert!(matches!(storage_err, StorageError::Io(_)));
        assert!(storage_err.to_string().contains("IO error"));
    }

    #[test]
    fn storage_error_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let storage_err = StorageError::Io(io_err);
        assert!(storage_err.source().is_some());

        let err = StorageError::NotInitialized;
        assert!(err.source().is_none());
    }

    #[test]
    fn private_key_debug_redacts_sensitive_data() {
        let raw = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let record = PrivateKeyRecord {
            raw: &raw,
            hex: "deadbeef00000001",
            decimal: "999999999",
            binary: "11011110101011011011111011101111",
            bit_length: 256,
            hamming_weight: 128,
            leading_zeros: 0,
        };

        let debug_output = format!("{:?}", record);

        assert!(!debug_output.contains("deadbeef"));
        assert!(!debug_output.contains("999999999"));
        assert!(!debug_output.contains("11011110"));
        assert!(debug_output.contains("[REDACTED]"));
        assert!(debug_output.contains("bit_length: 256"));
    }
}
