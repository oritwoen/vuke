//! Input wrapper for transform operations.

/// Input data that can be transformed into a private key.
///
/// Contains multiple representations of the same value for different transforms.
#[derive(Clone)]
pub struct Input {
    /// Original u64 value (for range sources)
    pub u64_val: Option<u64>,
    /// String representation
    pub string_val: String,
    /// Big-endian bytes (8 bytes)
    pub bytes_be: Option<[u8; 8]>,
    /// Little-endian bytes (8 bytes)
    pub bytes_le: Option<[u8; 8]>,
}

impl Input {
    /// Create input from a u64 value
    pub fn from_u64(val: u64) -> Self {
        Self {
            u64_val: Some(val),
            string_val: val.to_string(),
            bytes_be: Some(val.to_be_bytes()),
            bytes_le: Some(val.to_le_bytes()),
        }
    }

    /// Create input from a string (passphrase)
    pub fn from_string(s: String) -> Self {
        Self {
            u64_val: None,
            string_val: s,
            bytes_be: None,
            bytes_le: None,
        }
    }
}
