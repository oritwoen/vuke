//! Milksad transform - MT19937 PRNG seeded by input.
//!
//! Simulates weak key generation using Mersenne Twister with predictable seeds.
//! This reproduces the vulnerability found in Libbitcoin Explorer (bx) where
//! keys were generated using MT19937 with weak 32-bit seeds.

use rand_mt::Mt;
use super::{Input, Key, Transform};

pub struct MilksadTransform;

impl Transform for MilksadTransform {
    fn name(&self) -> &'static str {
        "milksad"
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        for input in inputs {
            if let Some(val) = input.u64_val {
                // MT19937 uses 32-bit seeds
                if val <= u32::MAX as u64 {
                    let mut rng = Mt::new(val as u32);
                    let mut key = [0u8; 32];
                    rng.fill_bytes(&mut key);
                    output.push((input.string_val.clone(), key));
                }
            }
        }
    }
}
