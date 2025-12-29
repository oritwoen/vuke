//! GPU context management.

use super::error::GpuError;
use std::sync::Arc;

/// GPU context holding device, queue, and adapter information.
pub struct GpuContext {
    pub device: Arc<wgpu::Device>,
    pub queue: Arc<wgpu::Queue>,
    pub adapter_info: wgpu::AdapterInfo,
}

/// GPU capabilities and limits.
#[derive(Debug, Clone)]
pub struct GpuCapabilities {
    pub max_workgroup_size_x: u32,
    pub max_workgroup_size_y: u32,
    pub max_workgroup_size_z: u32,
    pub max_compute_invocations_per_workgroup: u32,
    pub max_storage_buffer_binding_size: u32,
    pub backend: wgpu::Backend,
}

impl GpuContext {
    /// Create a new GPU context.
    ///
    /// This is async because wgpu adapter and device requests are async.
    /// Use `pollster::block_on` to call from sync code.
    pub async fn new() -> Result<Self, GpuError> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });

        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
            .ok_or(GpuError::NoAdapter)?;

        let adapter_info = adapter.get_info();

        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("vuke-gpu"),
                    required_features: wgpu::Features::empty(),
                    required_limits: wgpu::Limits::default(),
                    memory_hints: wgpu::MemoryHints::Performance,
                },
                None,
            )
            .await?;

        Ok(Self {
            device: Arc::new(device),
            queue: Arc::new(queue),
            adapter_info,
        })
    }

    /// Create a new GPU context synchronously.
    pub fn new_sync() -> Result<Self, GpuError> {
        pollster::block_on(Self::new())
    }

    /// Check if a GPU is available without fully initializing.
    pub fn is_available() -> bool {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });

        pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
        }))
        .is_some()
    }

    /// Get GPU capabilities.
    pub fn capabilities(&self) -> GpuCapabilities {
        let limits = self.device.limits();

        GpuCapabilities {
            max_workgroup_size_x: limits.max_compute_workgroup_size_x,
            max_workgroup_size_y: limits.max_compute_workgroup_size_y,
            max_workgroup_size_z: limits.max_compute_workgroup_size_z,
            max_compute_invocations_per_workgroup: limits.max_compute_invocations_per_workgroup,
            max_storage_buffer_binding_size: limits.max_storage_buffer_binding_size,
            backend: self.adapter_info.backend,
        }
    }

    /// Get a human-readable description of the GPU.
    pub fn description(&self) -> String {
        format!(
            "{} ({:?})",
            self.adapter_info.name, self.adapter_info.backend
        )
    }
}
