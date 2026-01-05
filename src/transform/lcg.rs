//! LCG transform - generates keys using Linear Congruential Generator.

use super::{Input, Key, Transform};
use crate::lcg::{generate_key, LcgEndian, LcgVariant, ALL_VARIANTS};

pub struct LcgTransform {
    variant: Option<LcgVariant>,
    endian: LcgEndian,
}

impl LcgTransform {
    pub fn new() -> Self {
        Self {
            variant: None,
            endian: LcgEndian::Big,
        }
    }

    pub fn with_variant(variant: LcgVariant) -> Self {
        Self {
            variant: Some(variant),
            endian: LcgEndian::Big,
        }
    }

    pub fn with_endian(mut self, endian: LcgEndian) -> Self {
        self.endian = endian;
        self
    }
}

impl Default for LcgTransform {
    fn default() -> Self {
        Self::new()
    }
}

impl Transform for LcgTransform {
    fn name(&self) -> &'static str {
        "lcg"
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        let variants: &[LcgVariant] = match &self.variant {
            Some(v) => std::slice::from_ref(v),
            None => &ALL_VARIANTS,
        };

        for input in inputs {
            if let Some(val) = input.u64_val {
                for variant in variants {
                    if val <= variant.max_seed() {
                        let key = generate_key(val as u32, variant, self.endian);
                        let source = if variants.len() > 1 {
                            match self.endian {
                                LcgEndian::Big => format!("{}:{}", input.string_val, variant.name),
                                LcgEndian::Little => format!(
                                    "{}:{}:{}",
                                    input.string_val,
                                    variant.name,
                                    self.endian.as_str()
                                ),
                            }
                        } else {
                            input.string_val.clone()
                        };
                        output.push((source, key));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lcg::{GLIBC, MINSTD};

    #[test]
    fn test_transform_single_variant() {
        let transform = LcgTransform::with_variant(GLIBC);
        let input = Input::from_u64(1);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 1);
        let expected = generate_key(1, &GLIBC, LcgEndian::Big);
        assert_eq!(output[0].1, expected);
    }

    #[test]
    fn test_transform_all_variants() {
        let transform = LcgTransform::new();
        let input = Input::from_u64(1);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 4);
    }

    #[test]
    fn test_transform_with_endian() {
        let transform_be = LcgTransform::with_variant(GLIBC);
        let transform_le = LcgTransform::with_variant(GLIBC).with_endian(LcgEndian::Little);

        let input = Input::from_u64(1);
        let mut output_be = Vec::new();
        let mut output_le = Vec::new();

        transform_be.apply_batch(&[input.clone()], &mut output_be);
        transform_le.apply_batch(&[input], &mut output_le);

        assert_ne!(output_be[0].1, output_le[0].1);
    }

    #[test]
    fn test_transform_seed_exceeds_max() {
        let transform = LcgTransform::with_variant(MINSTD);
        let input = Input::from_u64(u64::MAX);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 0);
    }

    #[test]
    fn test_source_format_single_variant() {
        let transform = LcgTransform::with_variant(GLIBC);
        let input = Input::from_u64(42);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output[0].0, "42");
    }

    #[test]
    fn test_source_format_all_variants() {
        let transform = LcgTransform::new();
        let input = Input::from_u64(42);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert!(output[0].0.contains("glibc"));
        assert!(output[1].0.contains("minstd"));
    }
}
