use crate::electrum::{ElectrumDeriver, truncate_seed};
use super::{Input, Key, Transform};

pub struct ElectrumTransform {
    derivation_count: u32,
    for_change: bool,
}

impl ElectrumTransform {
    pub fn new() -> Self {
        Self {
            derivation_count: 20,
            for_change: false,
        }
    }

    pub fn with_derivation_count(mut self, count: u32) -> Self {
        self.derivation_count = count;
        self
    }

    pub fn with_change(mut self) -> Self {
        self.for_change = true;
        self
    }
}

impl Default for ElectrumTransform {
    fn default() -> Self {
        Self::new()
    }
}

impl Transform for ElectrumTransform {
    fn name(&self) -> &'static str {
        if self.for_change {
            "electrum:change"
        } else {
            "electrum"
        }
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        for input in inputs {
            let seed = &input.string_val;
            
            let deriver = match ElectrumDeriver::from_hex_seed(seed) {
                Ok(d) => if self.for_change { d.with_change() } else { d },
                Err(_) => continue,
            };

            let chain = if self.for_change { "1" } else { "0" };
            
            for i in 0..self.derivation_count {
                if let Ok(key) = deriver.derive_key(i) {
                    let source = format!("{}[{}/{}]", truncate_seed(seed), chain, i);
                    output.push((source, key));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &str = "acb740e454c3134901d7c8f16497cc1c";

    #[test]
    fn test_electrum_transform_basic() {
        let transform = ElectrumTransform::new().with_derivation_count(1);
        let input = Input::from_string(TEST_SEED.to_string());
        
        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);
        
        assert_eq!(output.len(), 1);
        assert!(output[0].0.contains("0/0"));
    }

    #[test]
    fn test_electrum_transform_multiple_keys() {
        let transform = ElectrumTransform::new().with_derivation_count(5);
        let input = Input::from_string(TEST_SEED.to_string());
        
        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);
        
        assert_eq!(output.len(), 5);
    }

    #[test]
    fn test_electrum_transform_change_chain() {
        let transform = ElectrumTransform::new().with_change().with_derivation_count(1);
        let input = Input::from_string(TEST_SEED.to_string());
        
        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);
        
        assert_eq!(output.len(), 1);
        assert!(output[0].0.contains("1/0"));
    }

    #[test]
    fn test_electrum_transform_invalid_seed() {
        let transform = ElectrumTransform::new();
        let input = Input::from_string("not_valid_hex!".to_string());
        
        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);
        
        assert!(output.is_empty());
    }
}
