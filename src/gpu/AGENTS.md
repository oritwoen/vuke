# GPU MODULE

WebGPU acceleration for compute-intensive cryptographic operations.

## STRUCTURE

```
gpu/
├── mod.rs           # Module exports
├── context.rs       # GpuContext - device initialization
├── error.rs         # GpuError enum
├── buffer.rs        # GPU buffer utilities
├── hash.rs          # SHA256/MD5 hash pipelines
├── mt19937.rs       # MT19937 brute-force pipeline
├── sha256_chain.rs  # SHA256 chain brute-force pipeline
└── shaders/
    ├── mod.rs       # Shader source constants
    ├── mt19937.wgsl # MT19937 brute-force shader
    ├── sha256.wgsl  # SHA256 hash shader
    └── md5.wgsl     # MD5 hash shader
```

## WHERE TO LOOK

| Task | Location |
|------|----------|
| Add new GPU algorithm | Create shader in `shaders/`, pipeline in `{algo}.rs` |
| GPU context issues | `context.rs` - device/adapter initialization |
| Buffer management | `buffer.rs` - staging, uniform, storage buffers |
| Shader debugging | Check WGSL in `shaders/*.wgsl` |

## CONVENTIONS

- **Feature-gated**: Entire module behind `#[cfg(feature = "gpu")]`
- **Fallback**: Always have CPU implementation, GPU is optional acceleration
- **Workgroup size**: Use 256 for compute shaders (good occupancy)
- **Atomic termination**: Use `atomicStore` for early exit on match
- **Batched processing**: Process seeds in batches to balance CPU-GPU transfer
- **Single-block hashing**: Shaders assume pre-padded 64-byte input blocks

## GPU CONTEXT

```rust
impl GpuContext {
    pub fn new_sync() -> Result<Self, GpuError>;
    pub fn description(&self) -> String;
}
```

Initialize once, reuse across operations.

## SHADER PATTERN

```wgsl
@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let seed = uniforms.start_seed + global_id.x;
    if atomicLoad(&result.found) != 0u { return; }  // Early termination
    // Algorithm...
    if match_found { atomicStore(&result.found, 1u); result.seed = seed; }
}
```

## BUFFER TYPES

| Type | Purpose | WGSL |
|------|---------|------|
| Uniform | Read-only params (seeds, targets) | `@group(0) @binding(0) var<uniform>` |
| Storage | Results, large data | `@group(0) @binding(1) var<storage, read_write>` |
| Staging | CPU ↔ GPU transfer | Not in shader |

## ADDING GPU SUPPORT

1. Check if operation is compute-bound (hash, brute-force)
2. Create WGSL shader in `shaders/{algo}.wgsl`
3. Add shader constant to `shaders/mod.rs`
4. Create pipeline in `{algo}.rs`
5. Implement `supports_gpu()` returning `true`
6. Implement `analyze_gpu()` or `apply_batch_gpu()`

## COMPLEXITY HOTSPOTS

| File | Lines | Reason |
|------|-------|--------|
| `sha256_chain.rs` | 662 | Hybrid CPU-GPU pipelining, cascade filtering |
| `hash.rs` | 538 | Multi-algorithm support, double SHA256 |

## DEPENDENCIES

```toml
wgpu = { version = "24", optional = true }
pollster = { version = "0.4", optional = true }
bytemuck = { version = "1.21", features = ["derive"], optional = true }
```

Enable with: `cargo build --features gpu`
