//! MD5 transform - hash input and expand to 32 bytes.

use super::{Input, Key, Transform};
use md5::{Digest, Md5};

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

    #[cfg(feature = "gpu")]
    fn supports_gpu(&self) -> bool {
        true
    }

    #[cfg(feature = "gpu")]
    fn apply_batch_gpu(
        &self,
        ctx: &crate::gpu::GpuContext,
        inputs: &[Input],
        output: &mut Vec<(String, Key)>,
    ) -> Result<(), crate::gpu::GpuError> {
        use crate::gpu::{hash::HashAlgorithm, GpuHashPipeline};

        let pipeline = GpuHashPipeline::new(ctx)?;
        let result = pipeline.process_batch(HashAlgorithm::Md5, inputs)?;

        for (idx, hash) in result.processed_indices.iter().zip(result.hashes.iter()) {
            output.push((inputs[*idx].string_val.clone(), *hash));
        }

        for input in result.cpu_fallback {
            let hash = Md5::digest(input.string_val.as_bytes());
            let mut key = [0u8; 32];
            key[0..16].copy_from_slice(&hash);
            key[16..32].copy_from_slice(&hash);
            output.push((input.string_val.clone(), key));
        }

        Ok(())
    }
}
