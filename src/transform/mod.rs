//! Key derivation transforms.
//!
//! Transforms convert input data (numbers, strings) into 32-byte private keys.

mod input;
mod direct;
mod sha256;
mod double_sha256;
mod md5;
mod milksad;
mod armory;

pub use input::Input;
pub use direct::DirectTransform;
pub use sha256::Sha256Transform;
pub use double_sha256::DoubleSha256Transform;
pub use md5::Md5Transform;
pub use milksad::MilksadTransform;
pub use armory::ArmoryTransform;

/// 32-byte private key
pub type Key = [u8; 32];

/// Transform trait for converting inputs to private keys
pub trait Transform: Send + Sync {
    /// Human-readable name for this transform
    fn name(&self) -> &'static str;

    /// Process a batch of inputs and append results to output buffer
    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>);
}

/// Available transform types
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum TransformType {
    Direct,
    Sha256,
    DoubleSha256,
    Md5,
    Milksad,
    Armory,
}

impl TransformType {
    /// Create a boxed transform instance
    pub fn create(self) -> Box<dyn Transform> {
        match self {
            TransformType::Direct => Box::new(DirectTransform),
            TransformType::Sha256 => Box::new(Sha256Transform),
            TransformType::DoubleSha256 => Box::new(DoubleSha256Transform),
            TransformType::Md5 => Box::new(Md5Transform),
            TransformType::Milksad => Box::new(MilksadTransform),
            TransformType::Armory => Box::new(ArmoryTransform::new()),
        }
    }
}
