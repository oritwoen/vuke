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
    /// Arbitrary binary data (for file-based transforms like bitimage)
    pub blob: Option<Vec<u8>>,
}

impl Input {
    /// Create input from a u64 value
    pub fn from_u64(val: u64) -> Self {
        Self {
            u64_val: Some(val),
            string_val: val.to_string(),
            bytes_be: Some(val.to_be_bytes()),
            bytes_le: Some(val.to_le_bytes()),
            blob: None,
        }
    }

    /// Create input from a string (passphrase)
    pub fn from_string(s: String) -> Self {
        Self {
            u64_val: None,
            string_val: s,
            bytes_be: None,
            bytes_le: None,
            blob: None,
        }
    }

    /// Create input from arbitrary bytes (for file-based transforms)
    ///
    /// # Arguments
    /// * `data` - The binary data (e.g., file contents)
    /// * `label` - Human-readable source description (e.g., file path)
    pub fn from_blob(data: Vec<u8>, label: String) -> Self {
        Self {
            u64_val: None,
            string_val: label,
            bytes_be: None,
            bytes_le: None,
            blob: Some(data),
        }
    }
}
