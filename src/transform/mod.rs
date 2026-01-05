//! Key derivation transforms.
//!
//! Transforms convert input data (numbers, strings) into 32-byte private keys.

mod armory;
mod bitimage;
mod direct;
mod double_sha256;
mod electrum;
mod input;
mod lcg;
mod md5;
mod milksad;
mod mt64;
mod multibit;
mod sha256;
mod sha256_chain;
mod xorshift;

pub use armory::ArmoryTransform;
pub use bitimage::BitimageTransform;
pub use direct::DirectTransform;
pub use double_sha256::DoubleSha256Transform;
pub use electrum::ElectrumTransform;
pub use input::Input;
pub use lcg::LcgTransform;
pub use md5::Md5Transform;
pub use milksad::MilksadTransform;
pub use mt64::Mt64Transform;
pub use multibit::MultibitTransform;
pub use sha256::Sha256Transform;
pub use sha256_chain::Sha256ChainTransform;
pub use xorshift::XorshiftTransform;

/// 32-byte private key
pub type Key = [u8; 32];

/// Transform trait for converting inputs to private keys
pub trait Transform: Send + Sync {
    /// Human-readable name for this transform
    fn name(&self) -> &'static str;

    /// Process a batch of inputs and append results to output buffer
    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>);

    /// Whether this transform supports GPU acceleration
    #[cfg(feature = "gpu")]
    fn supports_gpu(&self) -> bool {
        false
    }

    /// Process a batch of inputs using GPU acceleration
    ///
    /// Default implementation falls back to CPU.
    #[cfg(feature = "gpu")]
    fn apply_batch_gpu(
        &self,
        _ctx: &crate::gpu::GpuContext,
        inputs: &[Input],
        output: &mut Vec<(String, Key)>,
    ) -> Result<(), crate::gpu::GpuError> {
        self.apply_batch(inputs, output);
        Ok(())
    }
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
    Electrum {
        for_change: bool,
    },
    Lcg {
        variant: Option<crate::lcg::LcgVariant>,
        endian: crate::lcg::LcgEndian,
    },
    Xorshift {
        variant: Option<crate::xorshift::XorshiftVariant>,
    },
    Sha256Chain {
        variant: Option<crate::sha256_chain::Sha256ChainVariant>,
        chain_depth: u32,
    },
    Bitimage {
        path: String,
        passphrase: String,
        passphrase_wordlist: Option<std::path::PathBuf>,
        derive_count: u32,
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
            TransformType::Electrum { for_change } => {
                let transform = if *for_change {
                    ElectrumTransform::new().with_change()
                } else {
                    ElectrumTransform::new()
                };
                Box::new(transform)
            }
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
            TransformType::Sha256Chain {
                variant,
                chain_depth,
            } => {
                let transform = match variant {
                    Some(v) => Sha256ChainTransform::with_variant(*v),
                    None => Sha256ChainTransform::new(),
                };
                Box::new(transform.with_chain_depth(*chain_depth))
            }
            TransformType::Bitimage {
                path,
                passphrase,
                passphrase_wordlist,
                derive_count,
            } => {
                let mut transform = BitimageTransform::new()
                    .with_path(path.clone())
                    .with_passphrase(passphrase.clone())
                    .with_derive_count(*derive_count);

                if let Some(wordlist_path) = passphrase_wordlist {
                    if let Err(e) = transform.with_passphrase_wordlist(wordlist_path.clone()) {
                        eprintln!(
                            "Warning: Failed to load passphrase wordlist '{}': {}",
                            wordlist_path.display(),
                            e
                        );
                    }
                }

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
            "electrum" => Ok(TransformType::Electrum { for_change: false }),
            "electrum:change" => Ok(TransformType::Electrum { for_change: true }),
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
            _ if s_lower == "sha256_chain" || s_lower.starts_with("sha256_chain:") => {
                let config = crate::sha256_chain::Sha256ChainConfig::parse(&s_lower)?;
                Ok(TransformType::Sha256Chain {
                    variant: config.variant,
                    chain_depth: config.chain_depth,
                })
            }
            "bitimage" => Ok(TransformType::Bitimage {
                path: "m/84'/0'/0'/0/0".to_string(),
                passphrase: String::new(),
                passphrase_wordlist: None,
                derive_count: 1,
            }),
            _ => Err(format!(
                "Unknown transform: {}. Valid: direct, sha256, double_sha256, md5, milksad, mt64, armory, multibit, electrum[:change], lcg[:variant][:endian], xorshift[:variant], sha256_chain[:variant], bitimage",
                s
            )),
        }
    }
}
