//! GPU-accelerated SHA256 chain brute-force search.
//!
//! Uses GpuHashPipeline for SHA256 computation with batched seed processing.

use super::{GpuContext, GpuError, GpuHashPipeline, HashAlgorithm};
use crate::sha256_chain::Sha256ChainVariant;

pub struct GpuSha256ChainSearchResult {
    pub seeds_tested: u64,
    pub found_seed: Option<u32>,
    pub found_variant: Option<Sha256ChainVariant>,
    pub found_chain_index: Option<u32>,
    pub found_full_key: Option<[u8; 32]>,
}

pub struct GpuSha256ChainPipeline {
    hash_pipeline: GpuHashPipeline,
}

impl GpuSha256ChainPipeline {
    pub fn new(ctx: &GpuContext) -> Result<Self, GpuError> {
        let hash_pipeline = GpuHashPipeline::new(ctx)?;
        Ok(Self { hash_pipeline })
    }

    /// Search for a seed that produces a key matching the target.
    ///
    /// This is a hybrid CPU-GPU approach:
    /// - CPU generates seed candidates and prepares hash inputs
    /// - GPU computes SHA256 hashes in batches
    /// - CPU checks results against target
    ///
    /// For Iterated variant, chains must be computed sequentially per seed.
    /// For Indexed variants, all keys in chain can be computed in parallel.
    pub fn search_exact(
        &self,
        target: &[u8; 32],
        variants: &[Sha256ChainVariant],
        chain_depth: u32,
        batch_size: u32,
        mut callback: impl FnMut(u64, Option<(u32, Sha256ChainVariant, u32)>) -> bool,
    ) -> Result<GpuSha256ChainSearchResult, GpuError> {
        let total_seeds = u32::MAX as u64 + 1;
        let mut seeds_tested: u64 = 0;
        let mut found_seed: Option<u32> = None;
        let mut found_variant: Option<Sha256ChainVariant> = None;
        let mut found_chain_index: Option<u32> = None;
        let mut found_full_key: Option<[u8; 32]> = None;

        let mut current_seed: u64 = 0;

        while current_seed < total_seeds {
            let batch_end = std::cmp::min(current_seed + batch_size as u64, total_seeds);
            let actual_batch_size = (batch_end - current_seed) as u32;

            for variant in variants {
                if found_seed.is_some() {
                    break;
                }

                match variant {
                    Sha256ChainVariant::Iterated => {
                        if let Some((seed, idx, key)) = self.search_batch_iterated(
                            current_seed as u32,
                            actual_batch_size,
                            chain_depth,
                            target,
                        )? {
                            found_seed = Some(seed);
                            found_variant = Some(*variant);
                            found_chain_index = Some(idx);
                            found_full_key = Some(key);
                        }
                    }
                    Sha256ChainVariant::IndexedBinary { big_endian } => {
                        if let Some((seed, idx, key)) = self.search_batch_indexed_binary(
                            current_seed as u32,
                            actual_batch_size,
                            chain_depth,
                            *big_endian,
                            target,
                        )? {
                            found_seed = Some(seed);
                            found_variant = Some(*variant);
                            found_chain_index = Some(idx);
                            found_full_key = Some(key);
                        }
                    }
                    Sha256ChainVariant::IndexedString => {
                        if let Some((seed, idx, key)) = self.search_batch_indexed_string(
                            current_seed as u32,
                            actual_batch_size,
                            chain_depth,
                            target,
                        )? {
                            found_seed = Some(seed);
                            found_variant = Some(*variant);
                            found_chain_index = Some(idx);
                            found_full_key = Some(key);
                        }
                    }
                }
            }

            seeds_tested = batch_end;

            let result = found_seed.map(|s| (s, found_variant.unwrap(), found_chain_index.unwrap()));
            if !callback(seeds_tested, result) {
                break;
            }

            if found_seed.is_some() {
                break;
            }

            current_seed = batch_end;
        }

        Ok(GpuSha256ChainSearchResult {
            seeds_tested,
            found_seed,
            found_variant,
            found_chain_index,
            found_full_key,
        })
    }

    fn search_batch_iterated(
        &self,
        start_seed: u32,
        batch_size: u32,
        chain_depth: u32,
        target: &[u8; 32],
    ) -> Result<Option<(u32, u32, [u8; 32])>, GpuError> {
        // For iterated variant: key[0] = SHA256(seed), key[n] = SHA256(key[n-1])
        // Step 1: Hash all seeds to get key[0]
        let mut inputs = Vec::with_capacity(batch_size as usize * 64);
        for i in 0..batch_size {
            let seed = start_seed.wrapping_add(i);
            let seed_bytes = seed.to_be_bytes();
            let block = GpuHashPipeline::pad_input_sha256(&seed_bytes)?;
            inputs.extend_from_slice(&block);
        }

        let mut current_keys = self.hash_pipeline.compute_batch(
            HashAlgorithm::Sha256,
            &inputs,
            batch_size,
        )?;

        // Check key[0] against target
        for (i, key) in current_keys.iter().enumerate() {
            if key == target {
                let seed = start_seed.wrapping_add(i as u32);
                return Ok(Some((seed, 0, *key)));
            }
        }

        // Iterate through chain
        for chain_idx in 1..chain_depth {
            // Prepare inputs: hash each current key
            let mut next_inputs = Vec::with_capacity(batch_size as usize * 64);
            for key in &current_keys {
                let block = GpuHashPipeline::pad_input_sha256(key)?;
                next_inputs.extend_from_slice(&block);
            }

            current_keys = self.hash_pipeline.compute_batch(
                HashAlgorithm::Sha256,
                &next_inputs,
                batch_size,
            )?;

            // Check against target
            for (i, key) in current_keys.iter().enumerate() {
                if key == target {
                    let seed = start_seed.wrapping_add(i as u32);
                    return Ok(Some((seed, chain_idx, *key)));
                }
            }
        }

        Ok(None)
    }

    fn search_batch_indexed_binary(
        &self,
        start_seed: u32,
        batch_size: u32,
        chain_depth: u32,
        big_endian: bool,
        target: &[u8; 32],
    ) -> Result<Option<(u32, u32, [u8; 32])>, GpuError> {
        // For indexed binary: key[n] = SHA256(seed || n as bytes)
        // Each key in chain is independent, can compute all at once per chain index

        for chain_idx in 0..chain_depth {
            let idx_bytes = if big_endian {
                chain_idx.to_be_bytes()
            } else {
                chain_idx.to_le_bytes()
            };

            let mut inputs = Vec::with_capacity(batch_size as usize * 64);
            for i in 0..batch_size {
                let seed = start_seed.wrapping_add(i);
                let seed_bytes = seed.to_be_bytes();

                // Concatenate seed || index (8 bytes total)
                let mut data = [0u8; 8];
                data[..4].copy_from_slice(&seed_bytes);
                data[4..8].copy_from_slice(&idx_bytes);

                let block = GpuHashPipeline::pad_input_sha256(&data)?;
                inputs.extend_from_slice(&block);
            }

            let hashes = self.hash_pipeline.compute_batch(
                HashAlgorithm::Sha256,
                &inputs,
                batch_size,
            )?;

            for (i, key) in hashes.iter().enumerate() {
                if key == target {
                    let seed = start_seed.wrapping_add(i as u32);
                    return Ok(Some((seed, chain_idx, *key)));
                }
            }
        }

        Ok(None)
    }

    fn search_batch_indexed_string(
        &self,
        start_seed: u32,
        batch_size: u32,
        chain_depth: u32,
        target: &[u8; 32],
    ) -> Result<Option<(u32, u32, [u8; 32])>, GpuError> {
        // For indexed string: key[n] = SHA256(seed || "n")
        // Each key in chain is independent

        for chain_idx in 0..chain_depth {
            let idx_str = chain_idx.to_string();
            let idx_bytes = idx_str.as_bytes();

            // Skip if concatenation would be too long for single block
            if 4 + idx_bytes.len() > 55 {
                // Fall back to CPU for this index
                continue;
            }

            let mut inputs = Vec::with_capacity(batch_size as usize * 64);
            for i in 0..batch_size {
                let seed = start_seed.wrapping_add(i);
                let seed_bytes = seed.to_be_bytes();

                // Concatenate seed || index_string
                let mut data = Vec::with_capacity(4 + idx_bytes.len());
                data.extend_from_slice(&seed_bytes);
                data.extend_from_slice(idx_bytes);

                let block = GpuHashPipeline::pad_input_sha256(&data)?;
                inputs.extend_from_slice(&block);
            }

            let hashes = self.hash_pipeline.compute_batch(
                HashAlgorithm::Sha256,
                &inputs,
                batch_size,
            )?;

            for (i, key) in hashes.iter().enumerate() {
                if key == target {
                    let seed = start_seed.wrapping_add(i as u32);
                    return Ok(Some((seed, chain_idx, *key)));
                }
            }
        }

        Ok(None)
    }

    /// Search for a seed that produces keys matching cascade targets.
    pub fn search_cascade(
        &self,
        targets: &[(u8, u64)],
        variants: &[Sha256ChainVariant],
        batch_size: u32,
        mut callback: impl FnMut(u64, Option<(u32, Sha256ChainVariant)>) -> bool,
    ) -> Result<GpuSha256ChainSearchResult, GpuError> {
        // For cascade, we need sequential keys from the same seed
        // This is harder to parallelize efficiently on GPU
        // Use hybrid approach: GPU for hash, CPU for cascade logic

        let total_seeds = u32::MAX as u64 + 1;
        let mut seeds_tested: u64 = 0;
        let mut found_seed: Option<u32> = None;
        let mut found_variant: Option<Sha256ChainVariant> = None;

        let mut current_seed: u64 = 0;

        while current_seed < total_seeds {
            let batch_end = std::cmp::min(current_seed + batch_size as u64, total_seeds);
            let actual_batch_size = (batch_end - current_seed) as u32;

            for variant in variants {
                if found_seed.is_some() {
                    break;
                }

                // Generate first key for all seeds in batch
                if let Some(seed) = self.search_cascade_for_variant(
                    current_seed as u32,
                    actual_batch_size,
                    targets,
                    *variant,
                )? {
                    found_seed = Some(seed);
                    found_variant = Some(*variant);
                }
            }

            seeds_tested = batch_end;

            let result = found_seed.map(|s| (s, found_variant.unwrap()));
            if !callback(seeds_tested, result) {
                break;
            }

            if found_seed.is_some() {
                break;
            }

            current_seed = batch_end;
        }

        Ok(GpuSha256ChainSearchResult {
            seeds_tested,
            found_seed,
            found_variant,
            found_chain_index: None,
            found_full_key: None,
        })
    }

    fn search_cascade_for_variant(
        &self,
        start_seed: u32,
        batch_size: u32,
        targets: &[(u8, u64)],
        variant: Sha256ChainVariant,
    ) -> Result<Option<u32>, GpuError> {
        if targets.is_empty() {
            return Ok(None);
        }

        let _chain_depth = targets.len() as u32;

        // For iterated variant, compute full chains and check cascade
        match variant {
            Sha256ChainVariant::Iterated => {
                self.check_cascade_iterated(start_seed, batch_size, targets)
            }
            Sha256ChainVariant::IndexedBinary { big_endian } => {
                self.check_cascade_indexed_binary(start_seed, batch_size, targets, big_endian)
            }
            Sha256ChainVariant::IndexedString => {
                self.check_cascade_indexed_string(start_seed, batch_size, targets)
            }
        }
    }

    fn check_cascade_iterated(
        &self,
        start_seed: u32,
        batch_size: u32,
        targets: &[(u8, u64)],
    ) -> Result<Option<u32>, GpuError> {
        // Compute key[0] for all seeds
        let mut inputs = Vec::with_capacity(batch_size as usize * 64);
        for i in 0..batch_size {
            let seed = start_seed.wrapping_add(i);
            let seed_bytes = seed.to_be_bytes();
            let block = GpuHashPipeline::pad_input_sha256(&seed_bytes)?;
            inputs.extend_from_slice(&block);
        }

        let mut current_keys = self.hash_pipeline.compute_batch(
            HashAlgorithm::Sha256,
            &inputs,
            batch_size,
        )?;

        // Track which seeds still match cascade
        let mut candidates: Vec<u32> = (0..batch_size).map(|i| start_seed.wrapping_add(i)).collect();

        for (chain_idx, (bits, target)) in targets.iter().enumerate() {
            // Filter candidates by current target
            let mut still_valid = Vec::new();
            let mut still_valid_keys = Vec::new();

            for (i, seed) in candidates.iter().enumerate() {
                let key = &current_keys[i];
                if check_mask(key, *bits, *target) {
                    still_valid.push(*seed);
                    still_valid_keys.push(*key);
                }
            }

            if still_valid.is_empty() {
                return Ok(None);
            }

            // If this is the last target and we have matches, return first
            if chain_idx == targets.len() - 1 {
                return Ok(Some(still_valid[0]));
            }

            // Compute next key for remaining candidates
            candidates = still_valid;
            let mut next_inputs = Vec::with_capacity(candidates.len() * 64);
            for key in &still_valid_keys {
                let block = GpuHashPipeline::pad_input_sha256(key)?;
                next_inputs.extend_from_slice(&block);
            }

            current_keys = self.hash_pipeline.compute_batch(
                HashAlgorithm::Sha256,
                &next_inputs,
                candidates.len() as u32,
            )?;
        }

        Ok(None)
    }

    fn check_cascade_indexed_binary(
        &self,
        start_seed: u32,
        batch_size: u32,
        targets: &[(u8, u64)],
        big_endian: bool,
    ) -> Result<Option<u32>, GpuError> {
        let mut candidates: Vec<u32> = (0..batch_size).map(|i| start_seed.wrapping_add(i)).collect();

        for (chain_idx, (bits, target)) in targets.iter().enumerate() {
            let idx_bytes = if big_endian {
                (chain_idx as u32).to_be_bytes()
            } else {
                (chain_idx as u32).to_le_bytes()
            };

            let mut inputs = Vec::with_capacity(candidates.len() * 64);
            for seed in &candidates {
                let seed_bytes = seed.to_be_bytes();
                let mut data = [0u8; 8];
                data[..4].copy_from_slice(&seed_bytes);
                data[4..8].copy_from_slice(&idx_bytes);
                let block = GpuHashPipeline::pad_input_sha256(&data)?;
                inputs.extend_from_slice(&block);
            }

            let hashes = self.hash_pipeline.compute_batch(
                HashAlgorithm::Sha256,
                &inputs,
                candidates.len() as u32,
            )?;

            let mut still_valid = Vec::new();
            for (i, seed) in candidates.iter().enumerate() {
                if check_mask(&hashes[i], *bits, *target) {
                    still_valid.push(*seed);
                }
            }

            if still_valid.is_empty() {
                return Ok(None);
            }

            if chain_idx == targets.len() - 1 {
                return Ok(Some(still_valid[0]));
            }

            candidates = still_valid;
        }

        Ok(None)
    }

    fn check_cascade_indexed_string(
        &self,
        start_seed: u32,
        batch_size: u32,
        targets: &[(u8, u64)],
    ) -> Result<Option<u32>, GpuError> {
        let mut candidates: Vec<u32> = (0..batch_size).map(|i| start_seed.wrapping_add(i)).collect();

        for (chain_idx, (bits, target)) in targets.iter().enumerate() {
            let idx_str = chain_idx.to_string();
            let idx_bytes = idx_str.as_bytes();

            if 4 + idx_bytes.len() > 55 {
                // Too long for GPU, skip
                return Ok(None);
            }

            let mut inputs = Vec::with_capacity(candidates.len() * 64);
            for seed in &candidates {
                let seed_bytes = seed.to_be_bytes();
                let mut data = Vec::with_capacity(4 + idx_bytes.len());
                data.extend_from_slice(&seed_bytes);
                data.extend_from_slice(idx_bytes);
                let block = GpuHashPipeline::pad_input_sha256(&data)?;
                inputs.extend_from_slice(&block);
            }

            let hashes = self.hash_pipeline.compute_batch(
                HashAlgorithm::Sha256,
                &inputs,
                candidates.len() as u32,
            )?;

            let mut still_valid = Vec::new();
            for (i, seed) in candidates.iter().enumerate() {
                if check_mask(&hashes[i], *bits, *target) {
                    still_valid.push(*seed);
                }
            }

            if still_valid.is_empty() {
                return Ok(None);
            }

            if chain_idx == targets.len() - 1 {
                return Ok(Some(still_valid[0]));
            }

            candidates = still_valid;
        }

        Ok(None)
    }
}

fn check_mask(key: &[u8; 32], bits: u8, target: u64) -> bool {
    if bits == 0 {
        return false;
    }
    let key_u64 = u64::from_be_bytes(key[24..32].try_into().unwrap());
    let mask: u64 = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let high_bit: u64 = 1u64 << (bits - 1);
    let masked = (key_u64 & mask) | high_bit;
    masked == target
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_chain::generate_chain;

    fn apply_mask(key: &[u8; 32], bits: u8) -> u64 {
        let key_u64 = u64::from_be_bytes(key[24..32].try_into().unwrap());
        let mask: u64 = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let high_bit: u64 = 1u64 << (bits - 1);
        (key_u64 & mask) | high_bit
    }

    fn generate_test_targets(
        seed: u32,
        variant: Sha256ChainVariant,
        bit_widths: &[u8],
    ) -> Vec<(u8, u64)> {
        let chain = generate_chain(&seed.to_be_bytes(), variant, bit_widths.len() as u32);
        bit_widths
            .iter()
            .zip(chain.iter())
            .map(|(&bits, key)| (bits, apply_mask(key, bits)))
            .collect()
    }

    #[test]
    fn test_check_mask() {
        let mut key = [0u8; 32];
        key[31] = 0x15;

        assert!(check_mask(&key, 5, 0x15));
        assert!(!check_mask(&key, 5, 0x16));
    }

    #[test]
    #[ignore] // Requires GPU
    fn test_gpu_search_exact_iterated() {
        let ctx = match pollster::block_on(GpuContext::new()) {
            Ok(ctx) => ctx,
            Err(_) => return,
        };

        let pipeline = GpuSha256ChainPipeline::new(&ctx).expect("Failed to create pipeline");

        let test_seed = 42u32;
        let variant = Sha256ChainVariant::Iterated;
        let chain = generate_chain(&test_seed.to_be_bytes(), variant, 3);
        let target = chain[1];

        let result = pipeline
            .search_exact(
                &target,
                &[variant],
                3,
                1000,
                |_, _| true,
            )
            .expect("Search failed");

        assert!(result.found_seed.is_some());
        assert_eq!(result.found_seed.unwrap(), test_seed);
        assert_eq!(result.found_chain_index.unwrap(), 1);
    }

    #[test]
    #[ignore] // Requires GPU
    fn test_gpu_cascade_iterated() {
        let ctx = match pollster::block_on(GpuContext::new()) {
            Ok(ctx) => ctx,
            Err(_) => return,
        };

        let pipeline = GpuSha256ChainPipeline::new(&ctx).expect("Failed to create pipeline");

        let test_seed = 100u32;
        let variant = Sha256ChainVariant::Iterated;
        let targets = generate_test_targets(test_seed, variant, &[5, 10, 15]);

        let result = pipeline
            .search_cascade(
                &targets,
                &[variant],
                10000,
                |_, _| true,
            )
            .expect("Search failed");

        assert!(result.found_seed.is_some());
        assert_eq!(result.found_seed.unwrap(), test_seed);
    }
}
