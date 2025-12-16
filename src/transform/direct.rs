//! Direct transform - use input bytes as private key.

use super::{Input, Key, Transform};

pub struct DirectTransform;

impl Transform for DirectTransform {
    fn name(&self) -> &'static str {
        "direct"
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        for input in inputs {
            // Big-endian: value in high bytes
            if let Some(be) = input.bytes_be {
                let mut key = [0u8; 32];
                key[24..].copy_from_slice(&be);
                output.push((input.string_val.clone(), key));
            }

            // Little-endian: value in low bytes
            if let Some(le) = input.bytes_le {
                let mut key = [0u8; 32];
                key[0..8].copy_from_slice(&le);
                output.push((input.string_val.clone(), key));
            }

            // String as bytes (if short enough)
            if input.string_val.len() <= 32 {
                let mut key = [0u8; 32];
                key[..input.string_val.len()].copy_from_slice(input.string_val.as_bytes());
                output.push((input.string_val.clone(), key));
            }
        }
    }
}
