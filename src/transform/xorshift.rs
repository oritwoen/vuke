//! Xorshift transform - generates keys using xorshift PRNG variants.

use crate::xorshift::{generate_key, XorshiftVariant, ALL_VARIANTS};
use super::{Input, Key, Transform};

pub struct XorshiftTransform {
    variant: Option<XorshiftVariant>,
}

impl XorshiftTransform {
    pub fn new() -> Self {
        Self { variant: None }
    }

    pub fn with_variant(variant: XorshiftVariant) -> Self {
        Self {
            variant: Some(variant),
        }
    }
}

impl Default for XorshiftTransform {
    fn default() -> Self {
        Self::new()
    }
}

impl Transform for XorshiftTransform {
    fn name(&self) -> &'static str {
        "xorshift"
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        let variants: &[XorshiftVariant] = match &self.variant {
            Some(v) => std::slice::from_ref(v),
            None => &ALL_VARIANTS,
        };

        for input in inputs {
            if let Some(seed) = input.u64_val {
                for variant in variants {
                    let key = generate_key(seed, *variant);
                    let source = if variants.len() > 1 {
                        format!("{}:{}", input.string_val, variant.name())
                    } else {
                        input.string_val.clone()
                    };
                    output.push((source, key));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_single_variant() {
        let transform = XorshiftTransform::with_variant(XorshiftVariant::Xorshift64);
        let input = Input::from_u64(12345);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 1);
        let expected = generate_key(12345, XorshiftVariant::Xorshift64);
        assert_eq!(output[0].1, expected);
    }

    #[test]
    fn test_transform_all_variants() {
        let transform = XorshiftTransform::new();
        let input = Input::from_u64(42);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 4);
    }

    #[test]
    fn test_transform_ignores_string_only_input() {
        let transform = XorshiftTransform::new();
        let input = Input::from_string("not a number".to_string());
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 0);
    }

    #[test]
    fn test_transform_handles_zero_seed() {
        let transform = XorshiftTransform::with_variant(XorshiftVariant::Xorshift64);
        let input = Input::from_u64(0);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 1);
        assert_ne!(output[0].1, [0u8; 32]);
    }

    #[test]
    fn test_source_format_single_variant() {
        let transform = XorshiftTransform::with_variant(XorshiftVariant::Xorshift64);
        let input = Input::from_u64(42);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output[0].0, "42");
    }

    #[test]
    fn test_source_format_all_variants() {
        let transform = XorshiftTransform::new();
        let input = Input::from_u64(42);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert!(output[0].0.contains("xorshift64"));
        assert!(output[1].0.contains("xorshift128"));
        assert!(output[2].0.contains("xorshift128+"));
        assert!(output[3].0.contains("xoroshiro128**"));
    }

    #[test]
    fn test_transform_handles_max_seed() {
        let transform = XorshiftTransform::with_variant(XorshiftVariant::Xorshift64);
        let input = Input::from_u64(u64::MAX);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 1);
    }
}
