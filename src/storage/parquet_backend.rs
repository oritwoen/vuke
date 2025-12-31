//! Parquet storage backend for persistent result storage.
//!
//! Implements `StorageBackend` using Apache Parquet format with zstd compression
//! for efficient TB-scale storage of generated keys.

use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use arrow::datatypes::Schema;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;

use super::{records_to_batch, result_schema, Result, ResultRecord, StorageBackend, StorageError};

/// Parquet-based storage backend for persistent result storage.
///
/// Uses Apache Parquet columnar format with configurable compression.
/// Writer is lazily initialized on first `write_batch` call.
///
/// # Example
///
/// ```no_run
/// use vuke::storage::{ParquetBackend, StorageBackend, ResultRecord};
///
/// let mut backend = ParquetBackend::new("results.parquet");
/// // backend.write_batch(&records)?;
/// // let path = backend.flush()?;
/// ```
pub struct ParquetBackend {
    path: PathBuf,
    writer: Mutex<Option<ArrowWriter<File>>>,
    schema: Arc<Schema>,
    compression: Compression,
}

impl ParquetBackend {
    /// Creates a new ParquetBackend with default zstd compression.
    ///
    /// The writer is lazily initialized on first `write_batch` call,
    /// so the file is not created until data is actually written.
    ///
    /// # Arguments
    ///
    /// * `path` - Output path for the Parquet file
    ///
    /// # Example
    ///
    /// ```no_run
    /// use vuke::storage::ParquetBackend;
    ///
    /// let backend = ParquetBackend::new("output.parquet");
    /// ```
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            writer: Mutex::new(None),
            schema: Arc::new(result_schema()),
            compression: Compression::ZSTD(Default::default()),
        }
    }

    /// Sets the compression algorithm for the Parquet file.
    ///
    /// # Arguments
    ///
    /// * `compression` - Compression algorithm (ZSTD, LZ4, SNAPPY, etc.)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use vuke::storage::ParquetBackend;
    /// use parquet::basic::Compression;
    ///
    /// let backend = ParquetBackend::new("output.parquet")
    ///     .with_compression(Compression::LZ4);
    /// ```
    pub fn with_compression(mut self, compression: Compression) -> Self {
        self.compression = compression;
        self
    }

    /// Returns the configured compression algorithm.
    pub fn compression(&self) -> Compression {
        self.compression
    }

    /// Returns the output path.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl StorageBackend for ParquetBackend {
    /// Writes a batch of records to the Parquet file.
    ///
    /// On first call, creates the output file and initializes the writer.
    /// Subsequent calls append to the same file.
    ///
    /// # Arguments
    ///
    /// * `records` - Slice of ResultRecords to write
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if file creation fails, or
    /// `StorageError::Parquet`/`StorageError::Arrow` if writing fails.
    fn write_batch(&mut self, records: &[ResultRecord<'_>]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let batch = records_to_batch(records)?;
        let mut guard = self.writer.lock().unwrap();

        if guard.is_none() {
            let file = File::create(&self.path)?;
            let props = WriterProperties::builder()
                .set_compression(self.compression)
                .build();
            let writer = ArrowWriter::try_new(file, self.schema.clone(), Some(props))?;
            *guard = Some(writer);
        }

        guard
            .as_mut()
            .ok_or(StorageError::NotInitialized)?
            .write(&batch)?;

        Ok(())
    }

    /// Finalizes the Parquet file and returns the output path.
    ///
    /// Closes the writer, writing the file footer. After this call,
    /// the backend cannot be used for further writes.
    ///
    /// If no data was written, returns the path without creating a file.
    ///
    /// # Returns
    ///
    /// The path to the written Parquet file.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Parquet` if closing the writer fails.
    fn flush(&mut self) -> Result<PathBuf> {
        let mut guard = self.writer.lock().unwrap();
        if let Some(writer) = guard.take() {
            writer.close()?;
        }
        Ok(self.path.clone())
    }

    /// Returns the Arrow schema used for this backend.
    fn schema(&self) -> &Schema {
        &self.schema
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
        let backend = ParquetBackend::new("test.parquet");
        assert_eq!(backend.path(), &PathBuf::from("test.parquet"));
        assert!(backend.writer.lock().unwrap().is_none());
    }

    #[test]
    fn schema_returns_result_schema() {
        let backend = ParquetBackend::new("test.parquet");
        let schema = backend.schema();
        assert_eq!(schema.fields().len(), 19);
        assert_eq!(schema.field(0).name(), "source");
    }

    #[test]
    fn with_compression_sets_compression() {
        let backend = ParquetBackend::new("test.parquet").with_compression(Compression::LZ4);
        assert!(matches!(backend.compression(), Compression::LZ4));

        let backend_zstd = ParquetBackend::new("test.parquet")
            .with_compression(Compression::ZSTD(ZstdLevel::try_new(3).unwrap()));
        assert!(matches!(backend_zstd.compression(), Compression::ZSTD(_)));
    }

    #[test]
    fn default_compression_is_zstd() {
        let backend = ParquetBackend::new("test.parquet");
        assert!(matches!(backend.compression(), Compression::ZSTD(_)));
    }

    #[test]
    fn write_empty_batch_succeeds() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.parquet");
        let mut backend = ParquetBackend::new(&path);

        let result = backend.write_batch(&[]);
        assert!(result.is_ok());
        assert!(backend.writer.lock().unwrap().is_none());
    }

    #[test]
    fn write_single_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("single.parquet");
        let mut backend = ParquetBackend::new(&path);

        let raw = [1u8; 32];
        let record = make_test_record(&raw, "test_source", &[], &[], &[], None);

        backend.write_batch(&[record]).unwrap();
        assert!(backend.writer.lock().unwrap().is_some());

        let result_path = backend.flush().unwrap();
        assert_eq!(result_path, path);
        assert!(path.exists());
    }

    #[test]
    fn write_multiple_batches() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("multi.parquet");
        let mut backend = ParquetBackend::new(&path);

        let raw1 = [1u8; 32];
        let raw2 = [2u8; 32];
        let raw3 = [3u8; 32];

        let record1 = make_test_record(&raw1, "source1", &[], &[], &[], None);
        let record2 = make_test_record(&raw2, "source2", &[], &[], &[], None);
        let record3 = make_test_record(&raw3, "source3", &[], &[], &[], None);

        backend.write_batch(&[record1]).unwrap();
        backend.write_batch(&[record2, record3]).unwrap();

        let result_path = backend.flush().unwrap();
        assert!(result_path.exists());
    }

    #[test]
    fn flush_returns_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("flush_test.parquet");
        let mut backend = ParquetBackend::new(&path);

        let raw = [1u8; 32];
        let record = make_test_record(&raw, "test", &[], &[], &[], None);
        backend.write_batch(&[record]).unwrap();

        let result_path = backend.flush().unwrap();
        assert_eq!(result_path, path);
    }

    #[test]
    fn flush_without_write_returns_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("no_write.parquet");
        let mut backend = ParquetBackend::new(&path);

        let result_path = backend.flush().unwrap();
        assert_eq!(result_path, path);
        assert!(!path.exists());
    }

    #[test]
    fn write_and_read_parquet_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("roundtrip.parquet");
        let mut backend = ParquetBackend::new(&path);

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
        let output_path = backend.flush().unwrap();

        let file = fs::File::open(&output_path).unwrap();
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

        let path_zstd = dir.path().join("zstd.parquet");
        let mut backend_zstd = ParquetBackend::new(&path_zstd);
        backend_zstd.write_batch(&records).unwrap();
        backend_zstd.flush().unwrap();

        let path_none = dir.path().join("none.parquet");
        let mut backend_none =
            ParquetBackend::new(&path_none).with_compression(Compression::UNCOMPRESSED);
        backend_none.write_batch(&records).unwrap();
        backend_none.flush().unwrap();

        let size_zstd = fs::metadata(&path_zstd).unwrap().len();
        let size_none = fs::metadata(&path_none).unwrap().len();

        assert!(
            size_zstd < size_none,
            "ZSTD ({} bytes) should be smaller than uncompressed ({} bytes)",
            size_zstd,
            size_none
        );
    }
}
