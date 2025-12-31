use anyhow::Result;

use super::Output;
use crate::derive::DerivedKey;
use crate::matcher::MatchInfo;

pub struct MultiOutput {
    outputs: Vec<Box<dyn Output>>,
}

impl MultiOutput {
    pub fn new(outputs: Vec<Box<dyn Output>>) -> Self {
        Self { outputs }
    }
}

impl Output for MultiOutput {
    fn key(&self, source: &str, transform: &str, derived: &DerivedKey) -> Result<()> {
        for output in &self.outputs {
            output.key(source, transform, derived)?;
        }
        Ok(())
    }

    fn hit(
        &self,
        source: &str,
        transform: &str,
        derived: &DerivedKey,
        match_info: &MatchInfo,
    ) -> Result<()> {
        for output in &self.outputs {
            output.hit(source, transform, derived, match_info)?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        for output in &self.outputs {
            output.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    struct CountingOutput {
        key_count: Arc<AtomicU64>,
        hit_count: Arc<AtomicU64>,
    }

    impl Output for CountingOutput {
        fn key(&self, _source: &str, _transform: &str, _derived: &DerivedKey) -> Result<()> {
            self.key_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn hit(
            &self,
            _source: &str,
            _transform: &str,
            _derived: &DerivedKey,
            _match_info: &MatchInfo,
        ) -> Result<()> {
            self.hit_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn flush(&self) -> Result<()> {
            Ok(())
        }
    }

    fn make_test_derived() -> DerivedKey {
        DerivedKey {
            raw: [1u8; 32],
            private_key_hex: "01".repeat(32),
            private_key_decimal: "1".to_string(),
            private_key_binary: "0".repeat(256),
            bit_length: 1,
            hamming_weight: 1,
            leading_zeros: 62,
            pubkey_compressed: "02abc".to_string(),
            pubkey_uncompressed: "04abc".to_string(),
            wif_compressed: "L1".to_string(),
            wif_uncompressed: "5J".to_string(),
            p2pkh_compressed: "1ABC".to_string(),
            p2pkh_uncompressed: "1DEF".to_string(),
            p2wpkh: "bc1q".to_string(),
        }
    }

    #[test]
    fn calls_all_outputs_on_key() {
        let count1 = Arc::new(AtomicU64::new(0));
        let count2 = Arc::new(AtomicU64::new(0));

        let out1 = CountingOutput {
            key_count: Arc::clone(&count1),
            hit_count: Arc::new(AtomicU64::new(0)),
        };
        let out2 = CountingOutput {
            key_count: Arc::clone(&count2),
            hit_count: Arc::new(AtomicU64::new(0)),
        };

        let multi = MultiOutput::new(vec![Box::new(out1), Box::new(out2)]);
        multi.key("src", "sha256", &make_test_derived()).unwrap();

        assert_eq!(count1.load(Ordering::Relaxed), 1);
        assert_eq!(count2.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn calls_all_outputs_on_hit() {
        let count1 = Arc::new(AtomicU64::new(0));
        let count2 = Arc::new(AtomicU64::new(0));

        let out1 = CountingOutput {
            key_count: Arc::new(AtomicU64::new(0)),
            hit_count: Arc::clone(&count1),
        };
        let out2 = CountingOutput {
            key_count: Arc::new(AtomicU64::new(0)),
            hit_count: Arc::clone(&count2),
        };

        let multi = MultiOutput::new(vec![Box::new(out1), Box::new(out2)]);
        let match_info = MatchInfo {
            address: "1ABC".to_string(),
            address_type: crate::matcher::AddressType::P2pkhCompressed,
        };
        multi
            .hit("src", "sha256", &make_test_derived(), &match_info)
            .unwrap();

        assert_eq!(count1.load(Ordering::Relaxed), 1);
        assert_eq!(count2.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn empty_multi_output() {
        let multi = MultiOutput::new(vec![]);
        multi.key("src", "sha256", &make_test_derived()).unwrap();
        multi.flush().unwrap();
    }
}
