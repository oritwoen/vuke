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
mod lcg;

pub use input::Input;
pub use direct::DirectTransform;
pub use sha256::Sha256Transform;
pub use double_sha256::DoubleSha256Transform;
pub use md5::Md5Transform;
pub use milksad::MilksadTransform;
pub use armory::ArmoryTransform;
pub use lcg::LcgTransform;

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
    Armory,
    Lcg {
        variant: Option<String>,
        endian: crate::lcg::LcgEndian,
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
            TransformType::Armory => Box::new(ArmoryTransform::new()),
            TransformType::Lcg { variant, endian } => {
                let transform = match variant {
                    Some(name) => {
                        let v = crate::lcg::LcgVariant::from_str(name)
                            .expect("Invalid LCG variant");
                        LcgTransform::with_variant(v)
                    }
                    None => LcgTransform::new(),
                };
                Box::new(transform.with_endian(*endian))
            }
        }
    }

    /// Parse transform type from string.
    /// 
    /// Formats:
    /// - "direct", "sha256", "double_sha256", "md5", "milksad", "armory" - simple transforms
    /// - "lcg" - all LCG variants, big-endian
    /// - "lcg:glibc" - specific variant, big-endian
    /// - "lcg:glibc:le" - specific variant, little-endian
    pub fn from_str(s: &str) -> Result<Self, String> {
        let s_lower = s.to_lowercase();
        
        match s_lower.as_str() {
            "direct" => Ok(TransformType::Direct),
            "sha256" => Ok(TransformType::Sha256),
            "double_sha256" => Ok(TransformType::DoubleSha256),
            "md5" => Ok(TransformType::Md5),
            "milksad" => Ok(TransformType::Milksad),
            "armory" => Ok(TransformType::Armory),
            _ if s_lower == "lcg" || s_lower.starts_with("lcg:") => Self::parse_lcg(&s_lower),
            _ => Err(format!(
                "Unknown transform: {}. Valid: direct, sha256, double_sha256, md5, milksad, armory, lcg[:variant][:endian]",
                s
            )),
        }
    }

    fn parse_lcg(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        
        let (variant, endian) = match parts.as_slice() {
            ["lcg"] => (None, crate::lcg::LcgEndian::Big),
            ["lcg", ""] => (None, crate::lcg::LcgEndian::Big),
            ["lcg", v] => {
                if let Some(e) = crate::lcg::LcgEndian::from_str(v) {
                    (None, e)
                } else if crate::lcg::LcgVariant::from_str(v).is_some() {
                    (Some(v.to_string()), crate::lcg::LcgEndian::Big)
                } else {
                    return Err(format!(
                        "Invalid LCG variant or endian: {}. Valid variants: glibc, minstd, msvc, borland. Valid endian: be, le",
                        v
                    ));
                }
            }
            ["lcg", "", e] => {
                let endian = crate::lcg::LcgEndian::from_str(e)
                    .ok_or_else(|| format!("Invalid endian: {}. Valid: be, le", e))?;
                (None, endian)
            }
            ["lcg", v, e] => {
                if crate::lcg::LcgVariant::from_str(v).is_none() {
                    return Err(format!(
                        "Invalid LCG variant: {}. Valid: glibc, minstd, msvc, borland",
                        v
                    ));
                }
                let endian = crate::lcg::LcgEndian::from_str(e)
                    .ok_or_else(|| format!("Invalid endian: {}. Valid: be, le", e))?;
                (Some(v.to_string()), endian)
            }
            _ => return Err("Invalid LCG format. Use: lcg, lcg:variant, lcg:variant:endian".to_string()),
        };
        
        Ok(TransformType::Lcg { variant, endian })
    }
}
