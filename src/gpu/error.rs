//! GPU error types.

use std::fmt;

/// Errors that can occur during GPU operations.
#[derive(Debug)]
pub enum GpuError {
    /// No suitable GPU adapter found
    NoAdapter,
    /// Failed to request GPU device
    DeviceRequest(wgpu::RequestDeviceError),
    /// Shader compilation failed
    ShaderCompilation(String),
    /// Buffer operation failed
    BufferOperation(String),
    /// GPU computation timed out
    Timeout,
    /// Generic GPU error
    Other(String),
}

impl fmt::Display for GpuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GpuError::NoAdapter => write!(f, "No suitable GPU adapter found"),
            GpuError::DeviceRequest(e) => write!(f, "Failed to request GPU device: {}", e),
            GpuError::ShaderCompilation(msg) => write!(f, "Shader compilation failed: {}", msg),
            GpuError::BufferOperation(msg) => write!(f, "Buffer operation failed: {}", msg),
            GpuError::Timeout => write!(f, "GPU computation timed out"),
            GpuError::Other(msg) => write!(f, "GPU error: {}", msg),
        }
    }
}

impl std::error::Error for GpuError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GpuError::DeviceRequest(e) => Some(e),
            _ => None,
        }
    }
}

impl From<wgpu::RequestDeviceError> for GpuError {
    fn from(err: wgpu::RequestDeviceError) -> Self {
        GpuError::DeviceRequest(err)
    }
}
