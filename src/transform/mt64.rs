//! MT19937-64 transform - generates keys using 64-bit seeded Mersenne Twister.

use super::{Input, Key, Transform};

pub struct Mt64Transform;

impl Transform for Mt64Transform {
    fn name(&self) -> &'static str {
        "mt64"
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        for input in inputs {
            if let Some(seed) = input.u64_val {
                let key = crate::mt64::generate_key(seed);
                output.push((input.string_val.clone(), key));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_generates_key() {
        let transform = Mt64Transform;
        let input = Input::from_u64(12345);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 1);
        assert_eq!(output[0].1, crate::mt64::generate_key(12345));
    }

    #[test]
    fn test_transform_ignores_string_only_input() {
        let transform = Mt64Transform;
        let input = Input::from_string("not a number".to_string());
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 0);
    }

    #[test]
    fn test_transform_handles_zero_seed() {
        let transform = Mt64Transform;
        let input = Input::from_u64(0);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 1);
        assert_eq!(output[0].0, "0");
    }

    #[test]
    fn test_transform_handles_max_seed() {
        let transform = Mt64Transform;
        let input = Input::from_u64(u64::MAX);
        let mut output = Vec::new();

        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 1);
    }
}
