//! Parquet storage output handler.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use chrono::Utc;

use parquet::basic::Compression;

use super::Output;
use crate::derive::DerivedKey;
use crate::matcher::MatchInfo;
use crate::storage::{
    AddressRecord, ExportFormatRecord, ParquetBackend, PrivateKeyRecord, PublicKeyRecord,
    ResultRecord, StorageBackend,
};

struct StorageInner {
    backend: Mutex<Option<ParquetBackend>>,
    records_written: AtomicU64,
    chain: String,
    base_dir: PathBuf,
    transform: String,
    chunk_records: u64,
    chunk_bytes: u64,
    compression: Compression,
}

#[derive(Clone)]
pub struct StorageOutput {
    inner: Arc<StorageInner>,
}

pub struct StorageSummary {
    pub paths: Vec<PathBuf>,
    pub records_written: u64,
}

impl StorageOutput {
    pub fn new(base_dir: impl AsRef<Path>, transform: &str) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        let compression = Compression::ZSTD(Default::default());
        let backend = ParquetBackend::new(&base_dir, transform).with_compression(compression);
        Ok(Self {
            inner: Arc::new(StorageInner {
                backend: Mutex::new(Some(backend)),
                records_written: AtomicU64::new(0),
                chain: "bitcoin".to_string(),
                base_dir,
                transform: transform.to_string(),
                chunk_records: 1_000_000,
                chunk_bytes: 100 * 1024 * 1024,
                compression,
            }),
        })
    }

    pub fn with_chunk_records(self, max_records: u64) -> Self {
        Self {
            inner: Arc::new(StorageInner {
                backend: Mutex::new(Some(
                    ParquetBackend::new(&self.inner.base_dir, &self.inner.transform)
                        .with_compression(self.inner.compression)
                        .with_chunk_records(max_records)
                        .with_chunk_bytes(self.inner.chunk_bytes),
                )),
                records_written: AtomicU64::new(0),
                chain: self.inner.chain.clone(),
                base_dir: self.inner.base_dir.clone(),
                transform: self.inner.transform.clone(),
                chunk_records: max_records,
                chunk_bytes: self.inner.chunk_bytes,
                compression: self.inner.compression,
            }),
        }
    }

    pub fn with_chunk_bytes(self, max_bytes: u64) -> Self {
        Self {
            inner: Arc::new(StorageInner {
                backend: Mutex::new(Some(
                    ParquetBackend::new(&self.inner.base_dir, &self.inner.transform)
                        .with_compression(self.inner.compression)
                        .with_chunk_records(self.inner.chunk_records)
                        .with_chunk_bytes(max_bytes),
                )),
                records_written: AtomicU64::new(0),
                chain: self.inner.chain.clone(),
                base_dir: self.inner.base_dir.clone(),
                transform: self.inner.transform.clone(),
                chunk_records: self.inner.chunk_records,
                chunk_bytes: max_bytes,
                compression: self.inner.compression,
            }),
        }
    }

    pub fn with_chain(self, chain: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(StorageInner {
                backend: Mutex::new(Some(
                    ParquetBackend::new(&self.inner.base_dir, &self.inner.transform)
                        .with_compression(self.inner.compression)
                        .with_chunk_records(self.inner.chunk_records)
                        .with_chunk_bytes(self.inner.chunk_bytes),
                )),
                records_written: AtomicU64::new(0),
                chain: chain.into(),
                base_dir: self.inner.base_dir.clone(),
                transform: self.inner.transform.clone(),
                chunk_records: self.inner.chunk_records,
                chunk_bytes: self.inner.chunk_bytes,
                compression: self.inner.compression,
            }),
        }
    }

    pub fn with_compression(self, compression: Compression) -> Self {
        Self {
            inner: Arc::new(StorageInner {
                backend: Mutex::new(Some(
                    ParquetBackend::new(&self.inner.base_dir, &self.inner.transform)
                        .with_compression(compression)
                        .with_chunk_records(self.inner.chunk_records)
                        .with_chunk_bytes(self.inner.chunk_bytes),
                )),
                records_written: AtomicU64::new(0),
                chain: self.inner.chain.clone(),
                base_dir: self.inner.base_dir.clone(),
                transform: self.inner.transform.clone(),
                chunk_records: self.inner.chunk_records,
                chunk_bytes: self.inner.chunk_bytes,
                compression,
            }),
        }
    }

    pub fn records_written(&self) -> u64 {
        self.inner.records_written.load(Ordering::Relaxed)
    }

    pub fn finish(self) -> Result<StorageSummary> {
        let mut guard = self.inner.backend.lock().unwrap();
        let paths = if let Some(mut backend) = guard.take() {
            backend.flush().map_err(|e| anyhow::anyhow!("{}", e))?
        } else {
            Vec::new()
        };
        Ok(StorageSummary {
            paths,
            records_written: self.inner.records_written.load(Ordering::Relaxed),
        })
    }

    fn write_record(
        &self,
        source: &str,
        transform: &str,
        derived: &DerivedKey,
        matched_target: Option<&str>,
    ) -> Result<()> {
        let public_keys = [
            PublicKeyRecord {
                format: "compressed",
                value: &derived.pubkey_compressed,
            },
            PublicKeyRecord {
                format: "uncompressed",
                value: &derived.pubkey_uncompressed,
            },
        ];

        let addresses = [
            AddressRecord {
                address_type: "p2pkh_compressed",
                address: &derived.p2pkh_compressed,
            },
            AddressRecord {
                address_type: "p2pkh_uncompressed",
                address: &derived.p2pkh_uncompressed,
            },
            AddressRecord {
                address_type: "p2wpkh",
                address: &derived.p2wpkh,
            },
        ];

        let export_formats = [
            ExportFormatRecord {
                format: "wif_compressed",
                value: &derived.wif_compressed,
            },
            ExportFormatRecord {
                format: "wif_uncompressed",
                value: &derived.wif_uncompressed,
            },
        ];

        let private_key = PrivateKeyRecord {
            raw: &derived.raw,
            hex: &derived.private_key_hex,
            decimal: &derived.private_key_decimal,
            binary: &derived.private_key_binary,
            bit_length: derived.bit_length,
            hamming_weight: derived.hamming_weight,
            leading_zeros: derived.leading_zeros,
        };

        let record = ResultRecord {
            source,
            transform,
            chain: &self.inner.chain,
            timestamp: Utc::now(),
            private_key,
            public_keys: &public_keys,
            addresses: &addresses,
            export_formats: &export_formats,
            matched_target,
        };

        let mut guard = self.inner.backend.lock().unwrap();
        if let Some(ref mut backend) = *guard {
            backend
                .write_batch(&[record])
                .map_err(|e| anyhow::anyhow!("{}", e))?;
        }

        self.inner.records_written.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

impl Output for StorageOutput {
    fn key(&self, source: &str, transform: &str, derived: &DerivedKey) -> Result<()> {
        self.write_record(source, transform, derived, None)
    }

    fn hit(
        &self,
        source: &str,
        transform: &str,
        derived: &DerivedKey,
        match_info: &MatchInfo,
    ) -> Result<()> {
        self.write_record(source, transform, derived, Some(&match_info.address))
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReader;
    use std::fs;
    use tempfile::tempdir;

    fn make_test_derived() -> DerivedKey {
        DerivedKey {
            raw: [1u8; 32],
            private_key_hex: "0101010101010101010101010101010101010101010101010101010101010101"
                .to_string(),
            private_key_decimal: "123456789".to_string(),
            private_key_binary: "0".repeat(256),
            bit_length: 249,
            hamming_weight: 32,
            leading_zeros: 0,
            pubkey_compressed: "02abc123".to_string(),
            pubkey_uncompressed: "04abc123def456".to_string(),
            wif_compressed: "L1234567890".to_string(),
            wif_uncompressed: "5J1234567890".to_string(),
            p2pkh_compressed: "1ABC123".to_string(),
            p2pkh_uncompressed: "1DEF456".to_string(),
            p2wpkh: "bc1qtest".to_string(),
        }
    }

    #[test]
    fn write_single_key() {
        let dir = tempdir().unwrap();
        let output = StorageOutput::new(dir.path(), "sha256").unwrap();

        output
            .key("test_source", "sha256", &make_test_derived())
            .unwrap();

        let summary = output.finish().unwrap();
        assert_eq!(summary.records_written, 1);
        assert_eq!(summary.paths.len(), 1);
        assert!(summary.paths[0].exists());
    }

    #[test]
    fn write_multiple_keys() {
        let dir = tempdir().unwrap();
        let output = StorageOutput::new(dir.path(), "milksad").unwrap();
        let derived = make_test_derived();

        for i in 0..10 {
            let source = format!("source_{}", i);
            output.key(&source, "milksad", &derived).unwrap();
        }

        let summary = output.finish().unwrap();
        assert_eq!(summary.records_written, 10);
    }

    #[test]
    fn write_hit_with_matched_target() {
        let dir = tempdir().unwrap();
        let output = StorageOutput::new(dir.path(), "sha256").unwrap();
        let derived = make_test_derived();

        let match_info = MatchInfo {
            address: "1ABC123".to_string(),
            address_type: crate::matcher::AddressType::P2pkhCompressed,
        };

        output
            .hit("test_source", "sha256", &derived, &match_info)
            .unwrap();

        let summary = output.finish().unwrap();
        assert_eq!(summary.records_written, 1);

        let file = fs::File::open(&summary.paths[0]).unwrap();
        let reader = ParquetRecordBatchReader::try_new(file, 1024).unwrap();
        let batches: Vec<_> = reader.map(|r| r.unwrap()).collect();

        assert_eq!(batches[0].num_rows(), 1);
        let matched_col = batches[0]
            .column(4)
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap();
        assert_eq!(matched_col.value(0), "1ABC123");
    }

    #[test]
    fn chunk_rotation() {
        let dir = tempdir().unwrap();
        let output = StorageOutput::new(dir.path(), "sha256")
            .unwrap()
            .with_chunk_records(3);
        let derived = make_test_derived();

        for i in 0..10 {
            let source = format!("source_{}", i);
            output.key(&source, "sha256", &derived).unwrap();
        }

        let summary = output.finish().unwrap();
        assert_eq!(summary.records_written, 10);
        assert!(summary.paths.len() >= 3);
    }

    #[test]
    fn records_written_counter() {
        let dir = tempdir().unwrap();
        let output = StorageOutput::new(dir.path(), "sha256").unwrap();
        let derived = make_test_derived();

        assert_eq!(output.records_written(), 0);

        output.key("source1", "sha256", &derived).unwrap();
        assert_eq!(output.records_written(), 1);

        output.key("source2", "sha256", &derived).unwrap();
        assert_eq!(output.records_written(), 2);
    }

    #[test]
    fn custom_chain() {
        let dir = tempdir().unwrap();
        let output = StorageOutput::new(dir.path(), "sha256")
            .unwrap()
            .with_chain("testnet");
        let derived = make_test_derived();

        output.key("test", "sha256", &derived).unwrap();
        let summary = output.finish().unwrap();

        let file = fs::File::open(&summary.paths[0]).unwrap();
        let reader = ParquetRecordBatchReader::try_new(file, 1024).unwrap();
        let batches: Vec<_> = reader.map(|r| r.unwrap()).collect();

        let chain_col = batches[0]
            .column(2)
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap();
        assert_eq!(chain_col.value(0), "testnet");
    }

    #[test]
    fn clone_shares_state() {
        let dir = tempdir().unwrap();
        let output1 = StorageOutput::new(dir.path(), "sha256").unwrap();
        let output2 = output1.clone();
        let derived = make_test_derived();

        output1.key("source1", "sha256", &derived).unwrap();
        output2.key("source2", "sha256", &derived).unwrap();

        assert_eq!(output1.records_written(), 2);
        assert_eq!(output2.records_written(), 2);

        let summary = output1.finish().unwrap();
        assert_eq!(summary.records_written, 2);
    }

    #[test]
    fn with_compression_creates_smaller_files() {
        use parquet::basic::ZstdLevel;

        let dir = tempdir().unwrap();
        let derived = make_test_derived();

        let dir_zstd = dir.path().join("zstd");
        let output_zstd = StorageOutput::new(&dir_zstd, "sha256")
            .unwrap()
            .with_compression(Compression::ZSTD(ZstdLevel::try_new(19).unwrap()));
        for i in 0..100 {
            let source = format!("source_{}", i);
            output_zstd.key(&source, "sha256", &derived).unwrap();
        }
        let summary_zstd = output_zstd.finish().unwrap();

        let dir_none = dir.path().join("none");
        let output_none = StorageOutput::new(&dir_none, "sha256")
            .unwrap()
            .with_compression(Compression::UNCOMPRESSED);
        for i in 0..100 {
            let source = format!("source_{}", i);
            output_none.key(&source, "sha256", &derived).unwrap();
        }
        let summary_none = output_none.finish().unwrap();

        let size_zstd = fs::metadata(&summary_zstd.paths[0]).unwrap().len();
        let size_none = fs::metadata(&summary_none.paths[0]).unwrap().len();

        assert!(
            size_zstd < size_none,
            "ZSTD ({} bytes) should be smaller than uncompressed ({} bytes)",
            size_zstd,
            size_none
        );
    }
}
