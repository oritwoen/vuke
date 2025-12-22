//! Key derivation transforms.
//!
//! Transforms convert input data (numbers, strings) into 32-byte private keys.

mod input;
mod direct;
mod sha256;
mod double_sha256;
mod md5;
mod milksad;
mod mt64;
mod armory;
mod lcg;
mod xorshift;
mod multibit;

pub use input::Input;
pub use direct::DirectTransform;
pub use sha256::Sha256Transform;
pub use double_sha256::DoubleSha256Transform;
pub use md5::Md5Transform;
pub use milksad::MilksadTransform;
pub use mt64::Mt64Transform;
pub use armory::ArmoryTransform;
pub use lcg::LcgTransform;
pub use xorshift::XorshiftTransform;
pub use multibit::MultibitTransform;

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
#[derive(Clone, Debug)]
pub enum TransformType {
    Direct,
    Sha256,
    DoubleSha256,
    Md5,
    Milksad,
    Mt64,
    Armory,
    Multibit,
    Lcg {
        variant: Option<crate::lcg::LcgVariant>,
        endian: crate::lcg::LcgEndian,
    },
    Xorshift {
        variant: Option<crate::xorshift::XorshiftVariant>,
    },
}

impl TransformType {
    /// Create a boxed transform instance
    pub fn create(&self) -> Box<dyn Transform> {
        match self {
            TransformType::Direct => Box::new(DirectTransform),
            TransformType::Sha256 => Box::new(Sha256Transform),
            TransformType::DoubleSha256 => Box::new(DoubleSha256Transform),
            TransformType::Md5 => Box::new(Md5Transform),
            TransformType::Milksad => Box::new(MilksadTransform),
            TransformType::Mt64 => Box::new(Mt64Transform),
            TransformType::Armory => Box::new(ArmoryTransform::new()),
            TransformType::Multibit => Box::new(MultibitTransform::new()),
            TransformType::Lcg { variant, endian } => {
                let transform = match variant {
                    Some(v) => LcgTransform::with_variant(*v),
                    None => LcgTransform::new(),
                };
                Box::new(transform.with_endian(*endian))
            }
            TransformType::Xorshift { variant } => {
                let transform = match variant {
                    Some(v) => XorshiftTransform::with_variant(*v),
                    None => XorshiftTransform::new(),
                };
                Box::new(transform)
            }
        }
    }

    pub fn from_str(s: &str) -> Result<Self, String> {
        let s_lower = s.to_lowercase();
        
        match s_lower.as_str() {
            "direct" => Ok(TransformType::Direct),
            "sha256" => Ok(TransformType::Sha256),
            "double_sha256" => Ok(TransformType::DoubleSha256),
            "md5" => Ok(TransformType::Md5),
            "milksad" => Ok(TransformType::Milksad),
            "mt64" => Ok(TransformType::Mt64),
            "armory" => Ok(TransformType::Armory),
            "multibit" => Ok(TransformType::Multibit),
            _ if s_lower == "lcg" || s_lower.starts_with("lcg:") => {
                let config = crate::lcg::LcgConfig::parse(&s_lower)?;
                Ok(TransformType::Lcg { 
                    variant: config.variant, 
                    endian: config.endian,
                })
            }
            _ if s_lower == "xorshift" || s_lower.starts_with("xorshift:") => {
                let config = crate::xorshift::XorshiftConfig::parse(&s_lower)?;
                Ok(TransformType::Xorshift {
                    variant: config.variant,
                })
            }
            _ => Err(format!(
                "Unknown transform: {}. Valid: direct, sha256, double_sha256, md5, milksad, mt64, armory, multibit, lcg[:variant][:endian], xorshift[:variant]",
                s
            )),
        }
    }
}
