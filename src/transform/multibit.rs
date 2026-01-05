//! MultiBit HD transform - reproduces the seed-as-entropy bug.

use super::{Input, Key, Transform};
use crate::multibit::{truncate_mnemonic, MultibitBugDeriver};

/// Transform that reproduces MultiBit HD Beta 7 seed-as-entropy bug.
///
/// Takes a BIP39 mnemonic (space-separated words) and derives keys
/// at path m/0'/0/i using the buggy derivation method.
pub struct MultibitTransform {
    derivation_count: u32,
    passphrase: String,
}

impl MultibitTransform {
    pub fn new() -> Self {
        Self {
            derivation_count: 20,
            passphrase: String::new(),
        }
    }

    pub fn with_derivation_count(mut self, count: u32) -> Self {
        self.derivation_count = count;
        self
    }

    pub fn with_passphrase(mut self, passphrase: String) -> Self {
        self.passphrase = passphrase;
        self
    }
}

impl Default for MultibitTransform {
    fn default() -> Self {
        Self::new()
    }
}

impl Transform for MultibitTransform {
    fn name(&self) -> &'static str {
        "multibit"
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        for input in inputs {
            let mnemonic = &input.string_val;

            match MultibitBugDeriver::from_mnemonic(mnemonic, &self.passphrase) {
                Ok(deriver) => {
                    for i in 0..self.derivation_count {
                        if let Ok(key) = deriver.derive_key(i) {
                            let source = format!("{}[m/0'/0/{}]", truncate_mnemonic(mnemonic), i);
                            output.push((source, key));
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multibit::truncate_mnemonic;

    #[test]
    fn test_multibit_transform_basic() {
        let transform = MultibitTransform::new().with_derivation_count(1);
        let input = Input::from_string(
            "skin join dog sponsor camera puppy ritual diagram arrow poverty boy elbow".to_string(),
        );

        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 1);
        assert!(output[0].0.contains("m/0'/0/0"));
    }

    #[test]
    fn test_multibit_transform_multiple_keys() {
        let transform = MultibitTransform::new().with_derivation_count(5);
        let input = Input::from_string(
            "skin join dog sponsor camera puppy ritual diagram arrow poverty boy elbow".to_string(),
        );

        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 5);
    }

    #[test]
    fn test_multibit_transform_invalid_mnemonic() {
        let transform = MultibitTransform::new();
        let input = Input::from_string("not a valid mnemonic".to_string());

        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);

        assert!(output.is_empty());
    }

    #[test]
    fn test_truncate_mnemonic() {
        let short = "one two three";
        assert_eq!(truncate_mnemonic(short), "one two three");

        let long = "one two three four five six seven eight nine ten eleven twelve";
        assert_eq!(truncate_mnemonic(long), "one two...eleven twelve");
    }
}
