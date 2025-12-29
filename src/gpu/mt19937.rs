//! GPU-accelerated MT19937 brute-force pipeline.

use super::{context::GpuContext, error::GpuError, shaders};
use bytemuck::{Pod, Zeroable};
use std::sync::Arc;

/// Workgroup size for MT19937 shader.
///
/// IMPORTANT: This value MUST match `@workgroup_size(N)` in mt19937.wgsl.
/// Using 128 for balance between occupancy and per-thread state (2496 bytes).
const WORKGROUP_SIZE: u32 = 128;

/// Parameters passed to the MT19937 shader.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Mt19937Params {
    seed_start: u32,
    seed_count: u32,
    _pad0: u32,
    _pad1: u32,
}

/// Double buffer set for pipelining
struct BufferSet {
    params: wgpu::Buffer,
    result: wgpu::Buffer,
    found: wgpu::Buffer,
    bind_group: wgpu::BindGroup,
}

/// GPU pipeline for MT19937 brute-force seed search.
///
/// Uses persistent buffers and double-buffering for optimal throughput.
pub struct GpuMt19937Pipeline {
    device: Arc<wgpu::Device>,
    queue: Arc<wgpu::Queue>,
    pipeline: wgpu::ComputePipeline,
    #[allow(dead_code)] // Kept for potential dynamic bind group creation
    bind_group_layout: wgpu::BindGroupLayout,
    // Persistent target buffer (shared between buffer sets)
    target_buffer: wgpu::Buffer,
    // Double buffer sets for pipelining
    buffer_sets: [BufferSet; 2],
}

/// Result of a GPU brute-force search.
#[derive(Debug, Clone)]
pub struct Mt19937SearchResult {
    /// The seed that was found, if any.
    pub found_seed: Option<u32>,
    /// Number of seeds tested.
    pub seeds_tested: u64,
}

impl GpuMt19937Pipeline {
    /// Create a new MT19937 GPU pipeline with pre-allocated buffers.
    pub fn new(ctx: &GpuContext) -> Result<Self, GpuError> {
        let shader = ctx
            .device
            .create_shader_module(wgpu::ShaderModuleDescriptor {
                label: Some("mt19937-shader"),
                source: wgpu::ShaderSource::Wgsl(shaders::MT19937_SHADER.into()),
            });

        let bind_group_layout =
            ctx.device
                .create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                    label: Some("mt19937-bind-group-layout"),
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
                        // Target key (storage, read-only)
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
                        // Result seed (storage, read-write)
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
                        // Found flag (storage, read-write)
                        wgpu::BindGroupLayoutEntry {
                            binding: 3,
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
                    label: Some("mt19937-pipeline-layout"),
                    bind_group_layouts: &[&bind_group_layout],
                    push_constant_ranges: &[],
                });

        let pipeline = ctx
            .device
            .create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: Some("mt19937-pipeline"),
                layout: Some(&pipeline_layout),
                module: &shader,
                entry_point: Some("main"),
                compilation_options: Default::default(),
                cache: None,
            });

        // Create persistent target buffer (32 bytes = 8 u32s)
        let target_buffer = ctx.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("mt19937-target"),
            size: 32,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // Create double buffer sets
        let buffer_sets = std::array::from_fn(|i| {
            let label_suffix = if i == 0 { "a" } else { "b" };

            let params = ctx.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(&format!("mt19937-params-{}", label_suffix)),
                size: std::mem::size_of::<Mt19937Params>() as u64,
                usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });

            let result = ctx.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(&format!("mt19937-result-{}", label_suffix)),
                size: 4,
                usage: wgpu::BufferUsages::STORAGE
                    | wgpu::BufferUsages::COPY_SRC
                    | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });

            let found = ctx.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(&format!("mt19937-found-{}", label_suffix)),
                size: 4,
                usage: wgpu::BufferUsages::STORAGE
                    | wgpu::BufferUsages::COPY_SRC
                    | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });

            let bind_group = ctx.device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some(&format!("mt19937-bind-group-{}", label_suffix)),
                layout: &bind_group_layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: params.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: target_buffer.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 2,
                        resource: result.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 3,
                        resource: found.as_entire_binding(),
                    },
                ],
            });

            BufferSet {
                params,
                result,
                found,
                bind_group,
            }
        });

        Ok(Self {
            device: ctx.device.clone(),
            queue: ctx.queue.clone(),
            pipeline,
            bind_group_layout,
            target_buffer,
            buffer_sets,
        })
    }

    /// Set the target key to search for.
    fn set_target(&self, target_key: &[u8; 32]) {
        // Convert to u32 array (little-endian, matching rand_mt)
        let target_u32: [u32; 8] = [
            u32::from_le_bytes([target_key[0], target_key[1], target_key[2], target_key[3]]),
            u32::from_le_bytes([target_key[4], target_key[5], target_key[6], target_key[7]]),
            u32::from_le_bytes([target_key[8], target_key[9], target_key[10], target_key[11]]),
            u32::from_le_bytes([target_key[12], target_key[13], target_key[14], target_key[15]]),
            u32::from_le_bytes([target_key[16], target_key[17], target_key[18], target_key[19]]),
            u32::from_le_bytes([target_key[20], target_key[21], target_key[22], target_key[23]]),
            u32::from_le_bytes([target_key[24], target_key[25], target_key[26], target_key[27]]),
            u32::from_le_bytes([target_key[28], target_key[29], target_key[30], target_key[31]]),
        ];
        self.queue
            .write_buffer(&self.target_buffer, 0, bytemuck::cast_slice(&target_u32));
    }

    /// Submit a batch for execution using the specified buffer set.
    fn submit_batch(&self, buffer_idx: usize, seed_start: u32, seed_count: u32) {
        let set = &self.buffer_sets[buffer_idx];

        // Update params
        let params = Mt19937Params {
            seed_start,
            seed_count,
            _pad0: 0,
            _pad1: 0,
        };
        self.queue
            .write_buffer(&set.params, 0, bytemuck::bytes_of(&params));

        // Reset result and found
        self.queue
            .write_buffer(&set.result, 0, bytemuck::bytes_of(&0u32));
        self.queue
            .write_buffer(&set.found, 0, bytemuck::bytes_of(&0u32));

        // Dispatch
        let workgroups = seed_count.div_ceil(WORKGROUP_SIZE);

        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("mt19937-encoder"),
            });

        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("mt19937-pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &set.bind_group, &[]);
            pass.dispatch_workgroups(workgroups, 1, 1);
        }

        self.queue.submit(Some(encoder.finish()));
    }

    /// Read results from a buffer set.
    fn read_results(&self, buffer_idx: usize) -> Option<u32> {
        let set = &self.buffer_sets[buffer_idx];

        let found_data =
            super::buffer::read_buffer_sync(&self.device, &self.queue, &set.found, 4);
        let found: u32 = bytemuck::cast_slice(&found_data)[0];

        if found != 0 {
            let result_data =
                super::buffer::read_buffer_sync(&self.device, &self.queue, &set.result, 4);
            let seed: u32 = bytemuck::cast_slice(&result_data)[0];
            Some(seed)
        } else {
            None
        }
    }

    /// Search for a seed that produces the target key.
    ///
    /// This searches the range [seed_start, seed_start + seed_count).
    /// Returns as soon as a match is found.
    pub fn search(
        &self,
        target_key: &[u8; 32],
        seed_start: u32,
        seed_count: u32,
    ) -> Result<Mt19937SearchResult, GpuError> {
        self.set_target(target_key);
        self.submit_batch(0, seed_start, seed_count);

        let found_seed = self.read_results(0);

        Ok(Mt19937SearchResult {
            found_seed,
            seeds_tested: seed_count as u64,
        })
    }

    /// Search the entire 32-bit seed space in batches with double-buffering.
    ///
    /// Uses pipelining: while GPU processes batch N, CPU reads results from batch N-1.
    /// Calls the progress callback with (seeds_tested, found_seed) periodically.
    pub fn search_full<F>(
        &self,
        target_key: &[u8; 32],
        batch_size: u32,
        mut progress: F,
    ) -> Result<Mt19937SearchResult, GpuError>
    where
        F: FnMut(u64, Option<u32>) -> bool,
    {
        self.set_target(target_key);

        let total: u64 = u32::MAX as u64 + 1;
        let mut seeds_tested: u64 = 0;
        let mut current_start: u64 = 0;

        // Submit first batch
        if current_start < total {
            let count = (total - current_start).min(batch_size as u64) as u32;
            self.submit_batch(0, current_start as u32, count);
            current_start += count as u64;
        }

        let mut active_buffer = 0usize;
        let mut pending_count = batch_size;

        while seeds_tested < total {
            // Submit next batch to alternate buffer (if more work remains)
            let next_buffer = 1 - active_buffer;
            let mut next_count = 0u32;

            if current_start < total {
                next_count = (total - current_start).min(batch_size as u64) as u32;
                self.submit_batch(next_buffer, current_start as u32, next_count);
                current_start += next_count as u64;
            }

            // Read results from current batch
            if let Some(seed) = self.read_results(active_buffer) {
                seeds_tested += pending_count as u64;
                progress(seeds_tested, Some(seed));
                return Ok(Mt19937SearchResult {
                    found_seed: Some(seed),
                    seeds_tested,
                });
            }

            seeds_tested += pending_count as u64;

            // Progress callback
            if !progress(seeds_tested, None) {
                return Ok(Mt19937SearchResult {
                    found_seed: None,
                    seeds_tested,
                });
            }

            // No more batches to process
            if next_count == 0 {
                break;
            }

            // Swap buffers
            active_buffer = next_buffer;
            pending_count = next_count;
        }

        Ok(Mt19937SearchResult {
            found_seed: None,
            seeds_tested,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_mt::Mt;

    #[test]
    #[ignore] // Requires GPU
    fn test_gpu_mt19937_finds_seed() {
        let ctx = match pollster::block_on(GpuContext::new()) {
            Ok(ctx) => ctx,
            Err(_) => return,
        };

        let pipeline = GpuMt19937Pipeline::new(&ctx).expect("Failed to create pipeline");

        let seed = 12345u32;
        let mut rng = Mt::new(seed);
        let mut target_key = [0u8; 32];
        rng.fill_bytes(&mut target_key);

        let result = pipeline.search(&target_key, 12300, 100).expect("Search failed");
        assert_eq!(result.found_seed, Some(seed));
    }

    #[test]
    #[ignore] // Requires GPU
    fn test_gpu_mt19937_seed_zero() {
        let ctx = match pollster::block_on(GpuContext::new()) {
            Ok(ctx) => ctx,
            Err(_) => return,
        };

        let pipeline = GpuMt19937Pipeline::new(&ctx).expect("Failed to create pipeline");

        let seed = 0u32;
        let mut rng = Mt::new(seed);
        let mut target_key = [0u8; 32];
        rng.fill_bytes(&mut target_key);

        let result = pipeline.search(&target_key, 0, 100).expect("Search failed");
        assert_eq!(result.found_seed, Some(seed));
    }

    #[test]
    #[ignore] // Requires GPU
    fn test_gpu_mt19937_not_found() {
        let ctx = match pollster::block_on(GpuContext::new()) {
            Ok(ctx) => ctx,
            Err(_) => return,
        };

        let pipeline = GpuMt19937Pipeline::new(&ctx).expect("Failed to create pipeline");
        let target_key = [0xdeu8; 32];

        let result = pipeline.search(&target_key, 0, 1000).expect("Search failed");
        assert_eq!(result.found_seed, None);
        assert_eq!(result.seeds_tested, 1000);
    }

    #[test]
    #[ignore] // Requires GPU
    fn test_gpu_mt19937_double_buffer() {
        let ctx = match pollster::block_on(GpuContext::new()) {
            Ok(ctx) => ctx,
            Err(_) => return,
        };

        let pipeline = GpuMt19937Pipeline::new(&ctx).expect("Failed to create pipeline");

        // Test with seed that requires multiple batches
        let seed = 500_000u32;
        let mut rng = Mt::new(seed);
        let mut target_key = [0u8; 32];
        rng.fill_bytes(&mut target_key);

        let result = pipeline
            .search_full(&target_key, 100_000, |_, _| true)
            .expect("Search failed");

        assert_eq!(result.found_seed, Some(seed));
    }
}
