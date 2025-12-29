//! GPU-accelerated hash transform pipelines.

use super::{buffer::GpuBufferFactory, context::GpuContext, error::GpuError, shaders};
use bytemuck::{Pod, Zeroable};
use std::sync::Arc;

/// Hash algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    DoubleSha256,
    Md5,
}

/// Parameters passed to hash shaders.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct HashParams {
    input_count: u32,
    input_stride: u32, // bytes per input (64 for single block)
    _pad0: u32,
    _pad1: u32,
}

/// GPU pipeline for batch hash computation.
pub struct GpuHashPipeline {
    device: Arc<wgpu::Device>,
    queue: Arc<wgpu::Queue>,
    sha256_pipeline: wgpu::ComputePipeline,
    md5_pipeline: wgpu::ComputePipeline,
    bind_group_layout: wgpu::BindGroupLayout,
    buffer_factory: GpuBufferFactory,
}

impl GpuHashPipeline {
    /// Create a new hash GPU pipeline.
    pub fn new(ctx: &GpuContext) -> Result<Self, GpuError> {
        let sha256_shader = ctx
            .device
            .create_shader_module(wgpu::ShaderModuleDescriptor {
                label: Some("sha256-shader"),
                source: wgpu::ShaderSource::Wgsl(shaders::SHA256_SHADER.into()),
            });

        let md5_shader = ctx
            .device
            .create_shader_module(wgpu::ShaderModuleDescriptor {
                label: Some("md5-shader"),
                source: wgpu::ShaderSource::Wgsl(shaders::MD5_SHADER.into()),
            });

        let bind_group_layout =
            ctx.device
                .create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                    label: Some("hash-bind-group-layout"),
                    entries: &[
                        // Params (uniform)
                        wgpu::BindGroupLayoutEntry {
                            binding: 0,
                            visibility: wgpu::ShaderStages::COMPUTE,
                            ty: wgpu::BindingType::Buffer {
                                ty: wgpu::BufferBindingType::Uniform,
                                has_dynamic_offset: false,
                                min_binding_size: None,
                            },
                            count: None,
                        },
                        // Inputs (storage, read-only)
                        wgpu::BindGroupLayoutEntry {
                            binding: 1,
                            visibility: wgpu::ShaderStages::COMPUTE,
                            ty: wgpu::BindingType::Buffer {
                                ty: wgpu::BufferBindingType::Storage { read_only: true },
                                has_dynamic_offset: false,
                                min_binding_size: None,
                            },
                            count: None,
                        },
                        // Outputs (storage, read-write)
                        wgpu::BindGroupLayoutEntry {
                            binding: 2,
                            visibility: wgpu::ShaderStages::COMPUTE,
                            ty: wgpu::BindingType::Buffer {
                                ty: wgpu::BufferBindingType::Storage { read_only: false },
                                has_dynamic_offset: false,
                                min_binding_size: None,
                            },
                            count: None,
                        },
                    ],
                });

        let pipeline_layout =
            ctx.device
                .create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
                    label: Some("hash-pipeline-layout"),
                    bind_group_layouts: &[&bind_group_layout],
                    push_constant_ranges: &[],
                });

        let sha256_pipeline =
            ctx.device
                .create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                    label: Some("sha256-pipeline"),
                    layout: Some(&pipeline_layout),
                    module: &sha256_shader,
                    entry_point: Some("main"),
                    compilation_options: Default::default(),
                    cache: None,
                });

        let md5_pipeline = ctx
            .device
            .create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: Some("md5-pipeline"),
                layout: Some(&pipeline_layout),
                module: &md5_shader,
                entry_point: Some("main"),
                compilation_options: Default::default(),
                cache: None,
            });

        Ok(Self {
            device: ctx.device.clone(),
            queue: ctx.queue.clone(),
            sha256_pipeline,
            md5_pipeline,
            bind_group_layout,
            buffer_factory: GpuBufferFactory::new(ctx),
        })
    }

    /// Compute hashes for a batch of inputs.
    ///
    /// Inputs should be pre-padded to 64 bytes each (single SHA256/MD5 block).
    /// Returns 32-byte hashes for each input.
    pub fn compute_batch(
        &self,
        algorithm: HashAlgorithm,
        inputs: &[u8],
        input_count: u32,
    ) -> Result<Vec<[u8; 32]>, GpuError> {
        const BLOCK_SIZE: u32 = 64;
        const WORKGROUP_SIZE: u32 = 256;

        if inputs.len() != (input_count as usize * BLOCK_SIZE as usize) {
            return Err(GpuError::BufferOperation(format!(
                "Expected {} bytes, got {}",
                input_count * BLOCK_SIZE,
                inputs.len()
            )));
        }

        // Create buffers
        let params = HashParams {
            input_count,
            input_stride: BLOCK_SIZE,
            _pad0: 0,
            _pad1: 0,
        };

        let params_buffer = self
            .buffer_factory
            .create_uniform_buffer_init("hash-params", bytemuck::bytes_of(&params));

        let input_buffer = self
            .buffer_factory
            .create_storage_buffer_init("hash-inputs", inputs);

        let output_size = (input_count as u64) * 32;
        let output_buffer = self.buffer_factory.create_read_buffer("hash-outputs", output_size);

        // Create bind group
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("hash-bind-group"),
            layout: &self.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: params_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: input_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: output_buffer.as_entire_binding(),
                },
            ],
        });

        // Select pipeline
        let pipeline = match algorithm {
            HashAlgorithm::Sha256 | HashAlgorithm::DoubleSha256 => &self.sha256_pipeline,
            HashAlgorithm::Md5 => &self.md5_pipeline,
        };

        let workgroups = input_count.div_ceil(WORKGROUP_SIZE);

        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("hash-encoder"),
            });

        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("hash-pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            pass.dispatch_workgroups(workgroups, 1, 1);
        }

        self.queue.submit(Some(encoder.finish()));

        // Read results
        let output_data =
            super::buffer::read_buffer_sync(&self.device, &self.queue, &output_buffer, output_size);

        // For double SHA256, we need to hash again
        let final_data = if algorithm == HashAlgorithm::DoubleSha256 {
            self.compute_second_sha256(&output_data, input_count)?
        } else {
            output_data
        };

        // Convert to array of [u8; 32]
        let mut results = Vec::with_capacity(input_count as usize);
        for chunk in final_data.chunks_exact(32) {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(chunk);
            results.push(hash);
        }

        Ok(results)
    }

    /// Compute second round of SHA256 for double SHA256.
    fn compute_second_sha256(
        &self,
        first_hashes: &[u8],
        count: u32,
    ) -> Result<Vec<u8>, GpuError> {
        // Pad each 32-byte hash to 64 bytes for second SHA256
        let mut padded = Vec::with_capacity(count as usize * 64);

        for chunk in first_hashes.chunks_exact(32) {
            // Copy hash
            padded.extend_from_slice(chunk);
            // Add padding: 0x80, zeros, length in bits (256 = 0x100)
            padded.push(0x80);
            padded.extend_from_slice(&[0u8; 23]); // Pad to 56 bytes
            // Length in bits (256) as big-endian u64
            padded.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 0]);
        }

        let params = HashParams {
            input_count: count,
            input_stride: 64,
            _pad0: 0,
            _pad1: 0,
        };

        let params_buffer = self
            .buffer_factory
            .create_uniform_buffer_init("hash2-params", bytemuck::bytes_of(&params));

        let input_buffer = self
            .buffer_factory
            .create_storage_buffer_init("hash2-inputs", &padded);

        let output_size = (count as u64) * 32;
        let output_buffer = self
            .buffer_factory
            .create_read_buffer("hash2-outputs", output_size);

        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("hash2-bind-group"),
            layout: &self.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: params_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: input_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: output_buffer.as_entire_binding(),
                },
            ],
        });

        const WORKGROUP_SIZE: u32 = 256;
        let workgroups = count.div_ceil(WORKGROUP_SIZE);

        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("hash2-encoder"),
            });

        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("hash2-pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.sha256_pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            pass.dispatch_workgroups(workgroups, 1, 1);
        }

        self.queue.submit(Some(encoder.finish()));

        Ok(super::buffer::read_buffer_sync(
            &self.device,
            &self.queue,
            &output_buffer,
            output_size,
        ))
    }

    /// Prepare input data for hashing.
    ///
    /// Pads the input to a single 64-byte SHA256/MD5 block.
    /// Input must be <= 55 bytes (to fit length in single block).
    ///
    /// Returns `Err` if input is too long for single block.
    pub fn pad_input_sha256(input: &[u8]) -> Result<[u8; 64], GpuError> {
        if input.len() > 55 {
            return Err(GpuError::BufferOperation(format!(
                "Input too long for single block: {} bytes (max 55)",
                input.len()
            )));
        }

        let mut block = [0u8; 64];
        block[..input.len()].copy_from_slice(input);
        block[input.len()] = 0x80;

        // Length in bits as big-endian u64
        let bit_len = (input.len() as u64) * 8;
        block[56..64].copy_from_slice(&bit_len.to_be_bytes());

        Ok(block)
    }

    /// Prepare input data for MD5 hashing.
    ///
    /// Pads the input to a single 64-byte MD5 block.
    /// Input must be <= 55 bytes (to fit length in single block).
    ///
    /// Returns `Err` if input is too long for single block.
    pub fn pad_input_md5(input: &[u8]) -> Result<[u8; 64], GpuError> {
        if input.len() > 55 {
            return Err(GpuError::BufferOperation(format!(
                "Input too long for single block: {} bytes (max 55)",
                input.len()
            )));
        }

        let mut block = [0u8; 64];
        block[..input.len()].copy_from_slice(input);
        block[input.len()] = 0x80;

        // Length in bits as little-endian u64
        let bit_len = (input.len() as u64) * 8;
        block[56..64].copy_from_slice(&bit_len.to_le_bytes());

        Ok(block)
    }
}

/// Maximum input length for single-block GPU hashing.
pub const MAX_SINGLE_BLOCK_INPUT_LEN: usize = 55;

/// Result of GPU batch hash preparation.
pub struct GpuBatchResult<'a> {
    /// Hashes computed on GPU (one per short input).
    pub hashes: Vec<[u8; 32]>,
    /// Indices of inputs that were processed on GPU.
    pub processed_indices: Vec<usize>,
    /// Inputs that need CPU fallback (too long for single block).
    pub cpu_fallback: Vec<&'a crate::transform::Input>,
}

impl GpuHashPipeline {
    /// Process a batch of inputs, computing hashes on GPU where possible.
    ///
    /// Returns GPU results and inputs requiring CPU fallback.
    /// This is a helper to reduce code duplication across transform implementations.
    pub fn process_batch<'a>(
        &self,
        algorithm: HashAlgorithm,
        inputs: &'a [crate::transform::Input],
    ) -> Result<GpuBatchResult<'a>, GpuError> {
        let mut short_inputs = Vec::new();
        let mut processed_indices = Vec::new();
        let mut cpu_fallback = Vec::new();

        for (i, input) in inputs.iter().enumerate() {
            if input.string_val.len() <= MAX_SINGLE_BLOCK_INPUT_LEN {
                short_inputs.push(input);
                processed_indices.push(i);
            } else {
                cpu_fallback.push(input);
            }
        }

        if short_inputs.is_empty() {
            return Ok(GpuBatchResult {
                hashes: Vec::new(),
                processed_indices: Vec::new(),
                cpu_fallback: inputs.iter().collect(),
            });
        }

        let pad_fn = match algorithm {
            HashAlgorithm::Sha256 | HashAlgorithm::DoubleSha256 => Self::pad_input_sha256,
            HashAlgorithm::Md5 => Self::pad_input_md5,
        };

        let mut padded_data = Vec::with_capacity(short_inputs.len() * 64);
        for input in &short_inputs {
            let block = pad_fn(input.string_val.as_bytes())?;
            padded_data.extend_from_slice(&block);
        }

        let hashes = self.compute_batch(algorithm, &padded_data, short_inputs.len() as u32)?;

        Ok(GpuBatchResult {
            hashes,
            processed_indices,
            cpu_fallback,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};
    use md5::Md5;

    #[test]
    #[ignore] // Requires GPU
    fn test_gpu_sha256_matches_cpu() {
        let ctx = match pollster::block_on(GpuContext::new()) {
            Ok(ctx) => ctx,
            Err(_) => return,
        };

        let pipeline = GpuHashPipeline::new(&ctx).expect("Failed to create pipeline");

        let test_inputs: &[&[u8]] = &[b"hello", b"world", b"test", b"gpu acceleration"];

        let mut padded_inputs = Vec::new();
        let mut expected: Vec<[u8; 32]> = Vec::new();

        for input in test_inputs {
            padded_inputs.extend_from_slice(&GpuHashPipeline::pad_input_sha256(input).unwrap());
            expected.push(Sha256::digest(input).into());
        }

        let gpu_results = pipeline
            .compute_batch(HashAlgorithm::Sha256, &padded_inputs, test_inputs.len() as u32)
            .expect("GPU compute failed");

        assert_eq!(gpu_results.len(), expected.len());
        for (i, (gpu, cpu)) in gpu_results.iter().zip(expected.iter()).enumerate() {
            assert_eq!(gpu, cpu, "SHA256 mismatch at index {}", i);
        }
    }

    #[test]
    #[ignore] // Requires GPU
    fn test_gpu_md5_matches_cpu() {
        let ctx = match pollster::block_on(GpuContext::new()) {
            Ok(ctx) => ctx,
            Err(_) => return,
        };

        let pipeline = GpuHashPipeline::new(&ctx).expect("Failed to create pipeline");

        let test_inputs: &[&[u8]] = &[b"hello", b"world", b"md5test"];

        let mut padded_inputs = Vec::new();
        let mut expected: Vec<[u8; 32]> = Vec::new();

        for input in test_inputs {
            padded_inputs.extend_from_slice(&GpuHashPipeline::pad_input_md5(input).unwrap());

            let result = Md5::digest(input);
            let mut hash = [0u8; 32];
            hash[..16].copy_from_slice(&result);
            hash[16..].copy_from_slice(&result);
            expected.push(hash);
        }

        let gpu_results = pipeline
            .compute_batch(HashAlgorithm::Md5, &padded_inputs, test_inputs.len() as u32)
            .expect("GPU compute failed");

        assert_eq!(gpu_results.len(), expected.len());
        for (i, (gpu, cpu)) in gpu_results.iter().zip(expected.iter()).enumerate() {
            assert_eq!(gpu, cpu, "MD5 mismatch at index {}", i);
        }
    }

    #[test]
    #[ignore] // Requires GPU
    fn test_gpu_double_sha256() {
        let ctx = match pollster::block_on(GpuContext::new()) {
            Ok(ctx) => ctx,
            Err(_) => return,
        };

        let pipeline = GpuHashPipeline::new(&ctx).expect("Failed to create pipeline");

        let input = b"double hash test";
        let padded = GpuHashPipeline::pad_input_sha256(input).unwrap();

        let first = Sha256::digest(input);
        let expected: [u8; 32] = Sha256::digest(&first).into();

        let gpu_results = pipeline
            .compute_batch(HashAlgorithm::DoubleSha256, &padded, 1)
            .expect("GPU compute failed");

        assert_eq!(gpu_results.len(), 1);
        assert_eq!(gpu_results[0], expected);
    }
}
