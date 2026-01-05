//! Bitimage transform - derive keys from file contents.

use super::{Input, Key, Transform};
use crate::bitimage::{increment_path_index, BitimageDeriver};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

pub struct BitimageTransform {
    path: String,
    passphrase: String,
    passphrase_wordlist: Option<Vec<String>>,
    derive_count: u32,
}

impl BitimageTransform {
    pub fn new() -> Self {
        Self {
            path: "m/84'/0'/0'/0/0".to_string(),
            passphrase: String::new(),
            passphrase_wordlist: None,
            derive_count: 1,
        }
    }

    pub fn with_path(mut self, path: String) -> Self {
        self.path = path;
        self
    }

    pub fn with_passphrase(mut self, passphrase: String) -> Self {
        self.passphrase = passphrase;
        self
    }

    pub fn with_passphrase_wordlist(&mut self, path: PathBuf) -> std::io::Result<()> {
        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let mut words = Vec::new();
        let mut line_num = 0;

        for line_result in reader.lines() {
            line_num += 1;
            match line_result {
                Ok(line) => {
                    let trimmed = line.trim().to_string();
                    if !trimmed.is_empty() {
                        words.push(trimmed);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to read line {} in '{}': {}",
                        line_num,
                        path.display(),
                        e
                    );
                }
            }
        }

        self.passphrase_wordlist = Some(words);
        Ok(())
    }

    pub fn with_derive_count(mut self, count: u32) -> Self {
        self.derive_count = count;
        self
    }

    fn derive_keys_for_passphrase(
        &self,
        data: &[u8],
        source_label: &str,
        passphrase: &str,
        output: &mut Vec<(String, Key)>,
    ) {
        let deriver = BitimageDeriver::from_file_bytes(data, passphrase);

        let mut current_path = self.path.clone();
        for i in 0..self.derive_count {
            match deriver.derive_path(&current_path) {
                Ok(key) => {
                    let source = if passphrase.is_empty() {
                        format!("{}[{}]", source_label, current_path)
                    } else {
                        format!("{}:{}[{}]", source_label, passphrase, current_path)
                    };
                    output.push((source, key));
                }
                Err(_) => continue,
            }

            if i + 1 < self.derive_count {
                current_path = increment_path_index(&current_path);
            }
        }
    }
}

impl Default for BitimageTransform {
    fn default() -> Self {
        Self::new()
    }
}

impl Transform for BitimageTransform {
    fn name(&self) -> &'static str {
        "bitimage"
    }

    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>) {
        for input in inputs {
            let data = match &input.blob {
                Some(blob) => blob.as_slice(),
                None => continue,
            };

            let source_label = &input.string_val;

            if let Some(wordlist) = &self.passphrase_wordlist {
                for passphrase in wordlist {
                    self.derive_keys_for_passphrase(data, source_label, passphrase, output);
                }
            } else {
                self.derive_keys_for_passphrase(data, source_label, &self.passphrase, output);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitimage_transform_basic() {
        let transform = BitimageTransform::new();
        let input = Input::from_blob(b"hello world".to_vec(), "test.jpg".to_string());

        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 1);
        assert!(output[0].0.contains("test.jpg"));
        assert!(output[0].0.contains("m/84'/0'/0'/0/0"));
    }

    #[test]
    fn test_bitimage_transform_multiple_derivations() {
        let transform = BitimageTransform::new().with_derive_count(3);
        let input = Input::from_blob(b"test data".to_vec(), "image.png".to_string());

        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 3);
        assert!(output[0].0.contains("/0/0]"));
        assert!(output[1].0.contains("/0/1]"));
        assert!(output[2].0.contains("/0/2]"));
    }

    #[test]
    fn test_bitimage_transform_with_passphrase() {
        let transform = BitimageTransform::new().with_passphrase("secret".to_string());
        let input = Input::from_blob(b"data".to_vec(), "file.bin".to_string());

        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);

        assert_eq!(output.len(), 1);
        assert!(output[0].0.contains(":secret["));
    }

    #[test]
    fn test_bitimage_transform_skips_non_blob_input() {
        let transform = BitimageTransform::new();
        let input = Input::from_string("just a string".to_string());

        let mut output = Vec::new();
        transform.apply_batch(&[input], &mut output);

        assert!(output.is_empty());
    }

    #[test]
    fn test_bitimage_transform_deterministic() {
        let transform = BitimageTransform::new();
        let input1 = Input::from_blob(b"same data".to_vec(), "file1.txt".to_string());
        let input2 = Input::from_blob(b"same data".to_vec(), "file2.txt".to_string());

        let mut output1 = Vec::new();
        let mut output2 = Vec::new();
        transform.apply_batch(&[input1], &mut output1);
        transform.apply_batch(&[input2], &mut output2);

        assert_eq!(output1[0].1, output2[0].1);
    }
}
