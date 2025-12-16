//! SHA256 transform - hash input to get private key.

use sha2::{Digest, Sha256};
use super::{Input, Key, Transform};

pub struct Sha256Transform;

impl Transform for Sha256Transform {
    fn name(&self) -> &'static str {
        "sha256"
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        for input in inputs {
            // Hash string representation
            let hash = Sha256::digest(input.string_val.as_bytes());
            output.push((input.string_val.clone(), hash.into()));

            // Hash big-endian bytes
            if let Some(be) = input.bytes_be {
                output.push((input.string_val.clone(), Sha256::digest(be).into()));
            }

            // Hash little-endian bytes
            if let Some(le) = input.bytes_le {
                output.push((input.string_val.clone(), Sha256::digest(le).into()));
            }
        }
    }
}
