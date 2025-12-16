//! MD5 transform - hash input and expand to 32 bytes.

use md5::{Digest, Md5};
use super::{Input, Key, Transform};

pub struct Md5Transform;

impl Transform for Md5Transform {
    fn name(&self) -> &'static str {
        "md5"
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        for input in inputs {
            // MD5 produces 16 bytes, duplicate to get 32
            let hash = Md5::digest(input.string_val.as_bytes());
            let mut key = [0u8; 32];
            key[0..16].copy_from_slice(&hash);
            key[16..32].copy_from_slice(&hash);
            output.push((input.string_val.clone(), key));
        }
    }
}
