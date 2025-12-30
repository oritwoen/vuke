use crate::sha256_chain::{
    generate_chain_from_string, Sha256ChainVariant, ALL_VARIANTS, DEFAULT_CHAIN_DEPTH,
};
use super::{Input, Key, Transform};

pub struct Sha256ChainTransform {
    variant: Option<Sha256ChainVariant>,
    chain_depth: u32,
}

impl Sha256ChainTransform {
    pub fn new() -> Self {
        Self {
            variant: None,
            chain_depth: DEFAULT_CHAIN_DEPTH,
        }
    }

    pub fn with_variant(variant: Sha256ChainVariant) -> Self {
        Self {
            variant: Some(variant),
            chain_depth: DEFAULT_CHAIN_DEPTH,
        }
    }

    pub fn with_chain_depth(mut self, depth: u32) -> Self {
        self.chain_depth = depth;
        self
    }

    fn variants_to_use(&self) -> Vec<Sha256ChainVariant> {
        match self.variant {
            Some(v) => vec![v],
            None => ALL_VARIANTS.to_vec(),
        }
    }
}

impl Default for Sha256ChainTransform {
    fn default() -> Self {
        Self::new()
    }
}

impl Transform for Sha256ChainTransform {
    fn name(&self) -> &'static str {
        match self.variant {
            Some(Sha256ChainVariant::Iterated) => "sha256_chain:iterated",
            Some(Sha256ChainVariant::IndexedBinary { big_endian: true }) => "sha256_chain:indexed:be",
            Some(Sha256ChainVariant::IndexedBinary { big_endian: false }) => "sha256_chain:indexed:le",
            Some(Sha256ChainVariant::IndexedString) => "sha256_chain:counter",
            None => "sha256_chain",
        }
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        let variants = self.variants_to_use();

        for input in inputs {
            let seed = &input.string_val;

            for variant in &variants {
                let chain = generate_chain_from_string(seed, *variant, self.chain_depth);

                for (idx, key) in chain.iter().enumerate() {
                    let source = format!("{}[{}:{}]", seed, variant.name(), idx);
                    output.push((source, *key));
                }
            }

            if let Some(num_val) = input.u64_val {
                if num_val > u32::MAX as u64 {
                    continue;
                }
                let seed_bytes = (num_val as u32).to_be_bytes();
                for variant in &variants {
                    let chain = crate::sha256_chain::generate_chain(&seed_bytes, *variant, self.chain_depth);

                    for (idx, key) in chain.iter().enumerate() {
                        let source = format!("{}[{}:{}]", input.string_val, variant.name(), idx);
                        output.push((source, *key));
                    }
                }
            }
        }
    }

    #[cfg(feature = "gpu")]
    fn supports_gpu(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_name() {
        assert_eq!(Sha256ChainTransform::new().name(), "sha256_chain");
        assert_eq!(
            Sha256ChainTransform::with_variant(Sha256ChainVariant::Iterated).name(),
            "sha256_chain:iterated"
        );
        assert_eq!(
            Sha256ChainTransform::with_variant(Sha256ChainVariant::IndexedBinary { big_endian: true }).name(),
            "sha256_chain:indexed:be"
        );
        assert_eq!(
            Sha256ChainTransform::with_variant(Sha256ChainVariant::IndexedBinary { big_endian: false }).name(),
            "sha256_chain:indexed:le"
        );
        assert_eq!(
            Sha256ChainTransform::with_variant(Sha256ChainVariant::IndexedString).name(),
            "sha256_chain:counter"
        );
    }

    #[test]
    fn test_transform_with_chain_depth() {
        let transform = Sha256ChainTransform::new().with_chain_depth(5);
        assert_eq!(transform.chain_depth, 5);
    }

    #[test]
    fn test_transform_generates_keys() {
        let transform = Sha256ChainTransform::with_variant(Sha256ChainVariant::Iterated)
            .with_chain_depth(3);
        let input = Input::from_string("test_seed".to_string());

        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 3);
        assert!(output[0].0.contains("iterated:0"));
        assert!(output[1].0.contains("iterated:1"));
        assert!(output[2].0.contains("iterated:2"));
    }

    #[test]
    fn test_transform_all_variants() {
        let transform = Sha256ChainTransform::new().with_chain_depth(2);
        let input = Input::from_string("seed".to_string());

        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 8);
    }

    #[test]
    fn test_transform_deterministic() {
        let transform = Sha256ChainTransform::with_variant(Sha256ChainVariant::Iterated)
            .with_chain_depth(2);
        let input = Input::from_string("deterministic".to_string());

        let mut output1 = Vec::new();
        let mut output2 = Vec::new();
        transform.apply_batch(&[input.clone()], &mut output1);
        transform.apply_batch(&[input], &mut output2);

        assert_eq!(output1.len(), output2.len());
        for (a, b) in output1.iter().zip(output2.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1, b.1);
        }
    }

    #[test]
    fn test_transform_numeric_input() {
        let transform = Sha256ChainTransform::with_variant(Sha256ChainVariant::Iterated)
            .with_chain_depth(2);
        let mut input = Input::from_string("12345".to_string());
        input.u64_val = Some(12345);

        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 4);
    }

    #[test]
    fn test_transform_keys_match_shared_logic() {
        let transform = Sha256ChainTransform::with_variant(Sha256ChainVariant::Iterated)
            .with_chain_depth(3);
        let input = Input::from_string("verification".to_string());

        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);

        let expected = generate_chain_from_string("verification", Sha256ChainVariant::Iterated, 3);

        for (i, (_, key)) in output.iter().enumerate() {
            assert_eq!(*key, expected[i], "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_transform_zero_depth() {
        let transform = Sha256ChainTransform::with_variant(Sha256ChainVariant::Iterated)
            .with_chain_depth(0);
        let input = Input::from_string("seed".to_string());

        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);

        assert!(output.is_empty());
    }
}
