//! Double SHA256 transform - SHA256(SHA256(input)).

use super::{Input, Key, Transform};
use sha2::{Digest, Sha256};

pub struct DoubleSha256Transform;

impl Transform for DoubleSha256Transform {
    fn name(&self) -> &'static str {
        "double_sha256"
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        for input in inputs {
            // Double hash string representation
            let hash1 = Sha256::digest(input.string_val.as_bytes());
            let hash2 = Sha256::digest(hash1);
            output.push((input.string_val.clone(), hash2.into()));

            // Double hash big-endian bytes
            if let Some(be) = input.bytes_be {
                let h1 = Sha256::digest(be);
                let h2 = Sha256::digest(h1);
                output.push((input.string_val.clone(), h2.into()));
            }

            if let Some(le) = input.bytes_le {
                let h1 = Sha256::digest(le);
                let h2 = Sha256::digest(h1);
                output.push((input.string_val.clone(), h2.into()));
            }
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
        let result = pipeline.process_batch(HashAlgorithm::DoubleSha256, inputs)?;

        for (idx, hash) in result.processed_indices.iter().zip(result.hashes.iter()) {
            output.push((inputs[*idx].string_val.clone(), *hash));
        }

        for input in result.cpu_fallback {
            let h1 = Sha256::digest(input.string_val.as_bytes());
            output.push((input.string_val.clone(), Sha256::digest(h1).into()));
        }

        for input in inputs {
            if let Some(be) = input.bytes_be {
                let h1 = Sha256::digest(be);
                output.push((input.string_val.clone(), Sha256::digest(h1).into()));
            }
            if let Some(le) = input.bytes_le {
                let h1 = Sha256::digest(le);
                output.push((input.string_val.clone(), Sha256::digest(h1).into()));
            }
        }

        Ok(())
    }
}
