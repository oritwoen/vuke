use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use arrow::datatypes::Schema;
use chrono::Utc;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;

use super::{records_to_batch, result_schema, Result, ResultRecord, StorageBackend, StorageError};

const DEFAULT_CHUNK_RECORDS: u64 = 1_000_000;
const DEFAULT_CHUNK_BYTES: u64 = 100 * 1024 * 1024;

pub struct ParquetBackend {
    base_dir: PathBuf,
    schema: Arc<Schema>,
    compression: Compression,
    max_chunk_records: Option<u64>,
    max_chunk_bytes: Option<u64>,
    writer: Mutex<Option<ArrowWriter<File>>>,
    current_chunk_path: Mutex<Option<PathBuf>>,
    chunk_index: Mutex<u32>,
    chunk_records: Mutex<u64>,
    chunk_bytes: Mutex<u64>,
    completed_chunks: Mutex<Vec<PathBuf>>,
    chunk_date: Mutex<Option<String>>,
}

impl ParquetBackend {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
            schema: Arc::new(result_schema()),
            compression: Compression::ZSTD(Default::default()),
            max_chunk_records: Some(DEFAULT_CHUNK_RECORDS),
            max_chunk_bytes: Some(DEFAULT_CHUNK_BYTES),
            writer: Mutex::new(None),
            current_chunk_path: Mutex::new(None),
            chunk_index: Mutex::new(0),
            chunk_records: Mutex::new(0),
            chunk_bytes: Mutex::new(0),
            completed_chunks: Mutex::new(Vec::new()),
            chunk_date: Mutex::new(None),
        }
    }

    pub fn with_compression(mut self, compression: Compression) -> Self {
        self.compression = compression;
        self
    }

    pub fn with_chunk_records(mut self, max_records: u64) -> Self {
        self.max_chunk_records = if max_records == 0 { None } else { Some(max_records) };
        self
    }

    pub fn with_chunk_bytes(mut self, max_bytes: u64) -> Self {
        self.max_chunk_bytes = if max_bytes == 0 { None } else { Some(max_bytes) };
        self
    }

    pub fn without_chunking(mut self) -> Self {
        self.max_chunk_records = None;
        self.max_chunk_bytes = None;
        self
    }

    pub fn compression(&self) -> Compression {
        self.compression
    }

    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    pub fn chunk_paths(&self) -> Vec<PathBuf> {
        self.completed_chunks.lock().unwrap().clone()
    }

    fn generate_chunk_path(&self) -> PathBuf {
        let mut date_guard = self.chunk_date.lock().unwrap();
        let date = date_guard.get_or_insert_with(|| Utc::now().format("%Y-%m-%d").to_string());

        let mut index_guard = self.chunk_index.lock().unwrap();
        *index_guard += 1;
        let index = *index_guard;

        self.base_dir.join(format!("{}_chunk_{:04}.parquet", date, index))
    }

    fn should_rotate(&self) -> bool {
        if let Some(max_records) = self.max_chunk_records {
            if *self.chunk_records.lock().unwrap() >= max_records {
                return true;
            }
        }
        if let Some(max_bytes) = self.max_chunk_bytes {
            if *self.chunk_bytes.lock().unwrap() >= max_bytes {
                return true;
            }
        }
        false
    }

    fn rotate_chunk(&mut self) -> Result<()> {
        let mut writer_guard = self.writer.lock()
            .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))?;

        if let Some(writer) = writer_guard.take() {
            writer.close()?;
        }

        if let Some(path) = self.current_chunk_path.lock()
            .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))?
            .take()
        {
            self.completed_chunks.lock()
                .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))?
                .push(path);
        }

        *self.chunk_records.lock()
            .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))? = 0;
        *self.chunk_bytes.lock()
            .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))? = 0;

        Ok(())
    }

    fn ensure_writer(&mut self) -> Result<()> {
        let mut writer_guard = self.writer.lock()
            .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))?;

        if writer_guard.is_none() {
            fs::create_dir_all(&self.base_dir)?;
            let chunk_path = self.generate_chunk_path();
            let file = File::create(&chunk_path)?;
            let props = WriterProperties::builder()
                .set_compression(self.compression)
                .build();
            let writer = ArrowWriter::try_new(file, self.schema.clone(), Some(props))?;
            *writer_guard = Some(writer);
            *self.current_chunk_path.lock()
                .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))? = Some(chunk_path);
        }

        Ok(())
    }
}

impl StorageBackend for ParquetBackend {
    fn write_batch(&mut self, records: &[ResultRecord<'_>]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        if self.should_rotate() {
            self.rotate_chunk()?;
        }

        self.ensure_writer()?;

        let batch = records_to_batch(records)?;
        let batch_bytes = batch.get_array_memory_size() as u64;

        {
            let mut writer_guard = self.writer.lock()
                .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))?;
            writer_guard
                .as_mut()
                .ok_or(StorageError::NotInitialized)?
                .write(&batch)?;
        }

        *self.chunk_records.lock()
            .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))? += records.len() as u64;
        *self.chunk_bytes.lock()
            .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))? += batch_bytes;

        Ok(())
    }

    fn flush(&mut self) -> Result<Vec<PathBuf>> {
        let mut writer_guard = self.writer.lock()
            .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))?;

        if let Some(writer) = writer_guard.take() {
            writer.close()?;
        }

        if let Some(path) = self.current_chunk_path.lock()
            .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))?
            .take()
        {
            self.completed_chunks.lock()
                .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))?
                .push(path);
        }

        Ok(self.completed_chunks.lock()
            .map_err(|e| StorageError::Other(format!("Mutex poisoned: {}", e)))?
            .clone())
    }

    fn schema(&self) -> &Schema {
        &self.schema
    }
}

impl Drop for ParquetBackend {
    fn drop(&mut self) {
        let has_unflushed = self.writer.lock()
            .map(|w| w.is_some())
            .unwrap_or(false);

        if has_unflushed {
            eprintln!(
                "Warning: ParquetBackend dropped with unflushed data. Call flush() before dropping."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{AddressRecord, ExportFormatRecord, PrivateKeyRecord, PublicKeyRecord};
    use arrow::array::Array;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReader;
    use parquet::basic::ZstdLevel;
    use std::fs;
    use tempfile::tempdir;

    fn make_test_record<'a>(
        raw: &'a [u8; 32],
        source: &'a str,
        public_keys: &'a [PublicKeyRecord<'a>],
        addresses: &'a [AddressRecord<'a>],
        export_formats: &'a [ExportFormatRecord<'a>],
        matched_target: Option<&'a str>,
    ) -> ResultRecord<'a> {
        ResultRecord {
            source,
            transform: "sha256",
            chain: "bitcoin",
            timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            private_key: PrivateKeyRecord {
                raw,
                hex: "0101010101010101010101010101010101010101010101010101010101010101",
                decimal: "454086624460063511464984254936031011189294057512315937409637584344757371137",
                binary: "0000000100000001000000010000000100000001000000010000000100000001\
                         0000000100000001000000010000000100000001000000010000000100000001\
                         0000000100000001000000010000000100000001000000010000000100000001\
                         0000000100000001000000010000000100000001000000010000000100000001",
                bit_length: 249,
                hamming_weight: 32,
                leading_zeros: 0,
            },
            public_keys,
            addresses,
            export_formats,
            matched_target,
        }
    }

    #[test]
    fn new_creates_backend() {
        let backend = ParquetBackend::new("results");
        assert_eq!(backend.base_dir(), &PathBuf::from("results"));
        assert!(backend.writer.lock().unwrap().is_none());
    }

    #[test]
    fn schema_returns_result_schema() {
        let backend = ParquetBackend::new("results");
        let schema = backend.schema();
        assert_eq!(schema.fields().len(), 19);
        assert_eq!(schema.field(0).name(), "source");
    }

    #[test]
    fn with_compression_sets_compression() {
        let backend = ParquetBackend::new("results").with_compression(Compression::LZ4);
        assert!(matches!(backend.compression(), Compression::LZ4));

        let backend_zstd = ParquetBackend::new("results")
            .with_compression(Compression::ZSTD(ZstdLevel::try_new(3).unwrap()));
        assert!(matches!(backend_zstd.compression(), Compression::ZSTD(_)));
    }

    #[test]
    fn default_compression_is_zstd() {
        let backend = ParquetBackend::new("results");
        assert!(matches!(backend.compression(), Compression::ZSTD(_)));
    }

    #[test]
    fn with_chunk_records_sets_threshold() {
        let backend = ParquetBackend::new("results").with_chunk_records(500_000);
        assert_eq!(backend.max_chunk_records, Some(500_000));
    }

    #[test]
    fn with_chunk_bytes_sets_threshold() {
        let backend = ParquetBackend::new("results").with_chunk_bytes(50 * 1024 * 1024);
        assert_eq!(backend.max_chunk_bytes, Some(50 * 1024 * 1024));
    }

    #[test]
    fn without_chunking_disables_thresholds() {
        let backend = ParquetBackend::new("results").without_chunking();
        assert_eq!(backend.max_chunk_records, None);
        assert_eq!(backend.max_chunk_bytes, None);
    }

    #[test]
    fn zero_threshold_disables_chunking() {
        let backend = ParquetBackend::new("results")
            .with_chunk_records(0)
            .with_chunk_bytes(0);
        assert_eq!(backend.max_chunk_records, None);
        assert_eq!(backend.max_chunk_bytes, None);
    }

    #[test]
    fn write_empty_batch_succeeds() {
        let dir = tempdir().unwrap();
        let mut backend = ParquetBackend::new(dir.path());

        let result = backend.write_batch(&[]);
        assert!(result.is_ok());
        assert!(backend.writer.lock().unwrap().is_none());
    }

    #[test]
    fn write_single_record() {
        let dir = tempdir().unwrap();
        let mut backend = ParquetBackend::new(dir.path());

        let raw = [1u8; 32];
        let record = make_test_record(&raw, "test_source", &[], &[], &[], None);

        backend.write_batch(&[record]).unwrap();
        assert!(backend.writer.lock().unwrap().is_some());

        let paths = backend.flush().unwrap();
        assert_eq!(paths.len(), 1);
        assert!(paths[0].exists());
        assert!(paths[0].to_string_lossy().contains("_chunk_0001.parquet"));
    }

    #[test]
    fn write_multiple_batches() {
        let dir = tempdir().unwrap();
        let mut backend = ParquetBackend::new(dir.path());

        let raw1 = [1u8; 32];
        let raw2 = [2u8; 32];
        let raw3 = [3u8; 32];

        let record1 = make_test_record(&raw1, "source1", &[], &[], &[], None);
        let record2 = make_test_record(&raw2, "source2", &[], &[], &[], None);
        let record3 = make_test_record(&raw3, "source3", &[], &[], &[], None);

        backend.write_batch(&[record1]).unwrap();
        backend.write_batch(&[record2, record3]).unwrap();

        let paths = backend.flush().unwrap();
        assert_eq!(paths.len(), 1);
        assert!(paths[0].exists());
    }

    #[test]
    fn flush_returns_paths() {
        let dir = tempdir().unwrap();
        let mut backend = ParquetBackend::new(dir.path());

        let raw = [1u8; 32];
        let record = make_test_record(&raw, "test", &[], &[], &[], None);
        backend.write_batch(&[record]).unwrap();

        let paths = backend.flush().unwrap();
        assert_eq!(paths.len(), 1);
        assert!(paths[0].exists());
    }

    #[test]
    fn flush_without_write_returns_empty() {
        let dir = tempdir().unwrap();
        let mut backend = ParquetBackend::new(dir.path());

        let paths = backend.flush().unwrap();
        assert!(paths.is_empty());
    }

    #[test]
    fn chunk_rotation_by_records() {
        let dir = tempdir().unwrap();
        let mut backend = ParquetBackend::new(dir.path())
            .with_chunk_records(2)
            .with_chunk_bytes(0);

        let raw = [1u8; 32];
        for i in 0..5 {
            let source: &'static str = Box::leak(format!("source_{}", i).into_boxed_str());
            let record = make_test_record(&raw, source, &[], &[], &[], None);
            backend.write_batch(&[record]).unwrap();
        }

        let paths = backend.flush().unwrap();
        assert_eq!(paths.len(), 3);
        assert!(paths[0].to_string_lossy().contains("_chunk_0001.parquet"));
        assert!(paths[1].to_string_lossy().contains("_chunk_0002.parquet"));
        assert!(paths[2].to_string_lossy().contains("_chunk_0003.parquet"));
    }

    #[test]
    fn chunk_rotation_by_bytes() {
        let dir = tempdir().unwrap();
        let mut backend = ParquetBackend::new(dir.path())
            .with_chunk_records(0)
            .with_chunk_bytes(1000);

        let raw = [0xab_u8; 32];
        for i in 0..10 {
            let source: &'static str = Box::leak(format!("source_{}", i).into_boxed_str());
            let record = make_test_record(&raw, source, &[], &[], &[], None);
            backend.write_batch(&[record]).unwrap();
        }

        let paths = backend.flush().unwrap();
        assert!(paths.len() >= 2, "Expected multiple chunks, got {}", paths.len());
        for path in &paths {
            assert!(path.exists());
        }
    }

    #[test]
    fn chunk_paths_returns_completed_chunks() {
        let dir = tempdir().unwrap();
        let mut backend = ParquetBackend::new(dir.path())
            .with_chunk_records(1)
            .with_chunk_bytes(0);

        let raw = [1u8; 32];
        let record1 = make_test_record(&raw, "source1", &[], &[], &[], None);
        let record2 = make_test_record(&raw, "source2", &[], &[], &[], None);

        backend.write_batch(&[record1]).unwrap();
        assert_eq!(backend.chunk_paths().len(), 0);

        backend.write_batch(&[record2]).unwrap();
        assert_eq!(backend.chunk_paths().len(), 1);
    }

    #[test]
    fn write_and_read_parquet_roundtrip() {
        let dir = tempdir().unwrap();
        let mut backend = ParquetBackend::new(dir.path());

        let raw1 = [0xab_u8; 32];
        let raw2 = [0xcd_u8; 32];

        let public_keys1 = [
            PublicKeyRecord {
                format: "compressed",
                value: "02abc123",
            },
            PublicKeyRecord {
                format: "uncompressed",
                value: "04abc123def",
            },
        ];
        let addresses1 = [
            AddressRecord {
                address_type: "p2pkh_compressed",
                address: "1ABC123",
            },
            AddressRecord {
                address_type: "p2wpkh",
                address: "bc1qtest",
            },
        ];
        let export_formats1 = [
            ExportFormatRecord {
                format: "wif_compressed",
                value: "L1234",
            },
            ExportFormatRecord {
                format: "wif_uncompressed",
                value: "5J1234",
            },
        ];

        let record1 = make_test_record(
            &raw1,
            "passphrase1",
            &public_keys1,
            &addresses1,
            &export_formats1,
            Some("1ABC123"),
        );
        let record2 = make_test_record(&raw2, "passphrase2", &[], &[], &[], None);

        backend.write_batch(&[record1, record2]).unwrap();
        let paths = backend.flush().unwrap();
        assert_eq!(paths.len(), 1);

        let file = fs::File::open(&paths[0]).unwrap();
        let reader = ParquetRecordBatchReader::try_new(file, 1024).unwrap();

        let batches: Vec<_> = reader.map(|r| r.unwrap()).collect();
        assert_eq!(batches.len(), 1);

        let batch = &batches[0];
        assert_eq!(batch.num_rows(), 2);
        assert_eq!(batch.num_columns(), 19);

        let source_col = batch
            .column(0)
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap();
        assert_eq!(source_col.value(0), "passphrase1");
        assert_eq!(source_col.value(1), "passphrase2");

        let matched_col = batch
            .column(4)
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap();
        assert!(!matched_col.is_null(0));
        assert_eq!(matched_col.value(0), "1ABC123");
        assert!(matched_col.is_null(1));

        let pubkey_col = batch
            .column(12)
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap();
        assert_eq!(pubkey_col.value(0), "02abc123");
        assert!(pubkey_col.is_null(1));

        let addr_col = batch
            .column(16)
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap();
        assert_eq!(addr_col.value(0), "bc1qtest");
        assert!(addr_col.is_null(1));
    }

    #[test]
    fn compression_affects_file_size() {
        let dir = tempdir().unwrap();
        let raw = [0xab_u8; 32];
        let records: Vec<_> = (0..100)
            .map(|i| {
                let source: &'static str = Box::leak(format!("source_{}", i).into_boxed_str());
                make_test_record(&raw, source, &[], &[], &[], None)
            })
            .collect();

        let dir_zstd = dir.path().join("zstd");
        let mut backend_zstd = ParquetBackend::new(&dir_zstd);
        backend_zstd.write_batch(&records).unwrap();
        let paths_zstd = backend_zstd.flush().unwrap();

        let dir_none = dir.path().join("none");
        let mut backend_none =
            ParquetBackend::new(&dir_none).with_compression(Compression::UNCOMPRESSED);
        backend_none.write_batch(&records).unwrap();
        let paths_none = backend_none.flush().unwrap();

        let size_zstd = fs::metadata(&paths_zstd[0]).unwrap().len();
        let size_none = fs::metadata(&paths_none[0]).unwrap().len();

        assert!(
            size_zstd < size_none,
            "ZSTD ({} bytes) should be smaller than uncompressed ({} bytes)",
            size_zstd,
            size_none
        );
    }

    #[test]
    fn read_all_chunks_integration() {
        let dir = tempdir().unwrap();
        let mut backend = ParquetBackend::new(dir.path())
            .with_chunk_records(2)
            .with_chunk_bytes(0);

        let raw = [1u8; 32];
        for i in 0..6 {
            let source: &'static str = Box::leak(format!("source_{}", i).into_boxed_str());
            let record = make_test_record(&raw, source, &[], &[], &[], None);
            backend.write_batch(&[record]).unwrap();
        }

        let paths = backend.flush().unwrap();
        assert_eq!(paths.len(), 3);

        let mut total_rows = 0;
        for path in &paths {
            let file = fs::File::open(path).unwrap();
            let reader = ParquetRecordBatchReader::try_new(file, 1024).unwrap();
            for batch in reader {
                total_rows += batch.unwrap().num_rows();
            }
        }
        assert_eq!(total_rows, 6);
    }
}
