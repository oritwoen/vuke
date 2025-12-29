//! WGSL shader sources.

/// MT19937 Mersenne Twister shader source.
pub const MT19937_SHADER: &str = include_str!("mt19937.wgsl");

/// SHA256 hash shader source.
pub const SHA256_SHADER: &str = include_str!("sha256.wgsl");

/// MD5 hash shader source.
pub const MD5_SHADER: &str = include_str!("md5.wgsl");
