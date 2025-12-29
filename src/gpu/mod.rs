//! GPU acceleration module using wgpu.
//!
//! Provides GPU-accelerated implementations for:
//! - MT19937 brute-force (milksad analyzer)
//! - Hash transforms (SHA256, MD5)

mod context;
mod error;
mod buffer;
mod shaders;
mod mt19937;
pub mod hash;

pub use context::GpuContext;
pub use error::GpuError;
pub use buffer::GpuBufferFactory;
pub use mt19937::GpuMt19937Pipeline;
pub use hash::{GpuHashPipeline, HashAlgorithm};
