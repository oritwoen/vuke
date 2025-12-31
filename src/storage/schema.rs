//! Arrow schema definition for result storage.
//!
//! Defines a flat Arrow schema that maps to `ResultRecord` for efficient
//! Parquet storage and querying via DuckDB/Polars.

use std::sync::Arc;

use arrow::array::{
    ArrayRef, FixedSizeBinaryBuilder, RecordBatch, StringArray, TimestampMillisecondArray,
    UInt16Array, UInt8Array,
};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::error::ArrowError;

use super::{AddressRecord, ExportFormatRecord, PublicKeyRecord, ResultRecord};

/// Field names for the result schema.
pub mod fields {
    // Core metadata
    pub const SOURCE: &str = "source";
    pub const TRANSFORM: &str = "transform";
    pub const CHAIN: &str = "chain";
    pub const TIMESTAMP: &str = "timestamp";
    pub const MATCHED_TARGET: &str = "matched_target";

    // Private key
    pub const PRIVATE_KEY_RAW: &str = "private_key_raw";
    pub const PRIVATE_KEY_HEX: &str = "private_key_hex";
    pub const PRIVATE_KEY_DECIMAL: &str = "private_key_decimal";
    pub const PRIVATE_KEY_BINARY: &str = "private_key_binary";
    pub const PRIVATE_KEY_BIT_LENGTH: &str = "private_key_bit_length";
    pub const PRIVATE_KEY_HAMMING_WEIGHT: &str = "private_key_hamming_weight";
    pub const PRIVATE_KEY_LEADING_ZEROS: &str = "private_key_leading_zeros";

    // Public keys
    pub const PUBKEY_COMPRESSED: &str = "pubkey_compressed";
    pub const PUBKEY_UNCOMPRESSED: &str = "pubkey_uncompressed";

    // Addresses
    pub const ADDRESS_P2PKH_COMPRESSED: &str = "address_p2pkh_compressed";
    pub const ADDRESS_P2PKH_UNCOMPRESSED: &str = "address_p2pkh_uncompressed";
    pub const ADDRESS_P2WPKH: &str = "address_p2wpkh";

    // Export formats
    pub const WIF_COMPRESSED: &str = "wif_compressed";
    pub const WIF_UNCOMPRESSED: &str = "wif_uncompressed";
}

/// Returns the Arrow schema for ResultRecord storage.
///
/// The schema is flat (no nested types) for easy querying with SQL-based tools.
/// Variable-length fields (public_keys, addresses, export_formats) are mapped
/// to fixed columns based on known Bitcoin formats.
///
/// # Schema (19 columns)
///
/// | Column | Type | Nullable | Description |
/// |--------|------|----------|-------------|
/// | source | Utf8 | No | Input value (seed, passphrase) |
/// | transform | Utf8 | No | Transform name (sha256, milksad) |
/// | chain | Utf8 | No | Blockchain (bitcoin, ethereum) |
/// | timestamp | Timestamp(ms, UTC) | No | Generation time |
/// | matched_target | Utf8 | Yes | Matched address (scan hits only) |
/// | private_key_raw | FixedSizeBinary(32) | No | Raw 32-byte key |
/// | private_key_hex | Utf8 | No | Hex representation |
/// | private_key_decimal | Utf8 | No | Decimal representation |
/// | private_key_binary | Utf8 | No | Binary representation (256 chars) |
/// | private_key_bit_length | UInt16 | No | Effective bit length |
/// | private_key_hamming_weight | UInt16 | No | Number of 1-bits |
/// | private_key_leading_zeros | UInt8 | No | Leading zeros in hex |
/// | pubkey_compressed | Utf8 | Yes | Compressed public key |
/// | pubkey_uncompressed | Utf8 | Yes | Uncompressed public key |
/// | address_p2pkh_compressed | Utf8 | Yes | P2PKH (compressed) |
/// | address_p2pkh_uncompressed | Utf8 | Yes | P2PKH (uncompressed) |
/// | address_p2wpkh | Utf8 | Yes | P2WPKH (native segwit) |
/// | wif_compressed | Utf8 | Yes | WIF compressed |
/// | wif_uncompressed | Utf8 | Yes | WIF uncompressed |
pub fn result_schema() -> Schema {
    Schema::new(vec![
        // Core metadata
        Field::new(fields::SOURCE, DataType::Utf8, false),
        Field::new(fields::TRANSFORM, DataType::Utf8, false),
        Field::new(fields::CHAIN, DataType::Utf8, false),
        Field::new(
            fields::TIMESTAMP,
            DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
            false,
        ),
        Field::new(fields::MATCHED_TARGET, DataType::Utf8, true),
        // Private key
        Field::new(
            fields::PRIVATE_KEY_RAW,
            DataType::FixedSizeBinary(32),
            false,
        ),
        Field::new(fields::PRIVATE_KEY_HEX, DataType::Utf8, false),
        Field::new(fields::PRIVATE_KEY_DECIMAL, DataType::Utf8, false),
        Field::new(fields::PRIVATE_KEY_BINARY, DataType::Utf8, false),
        Field::new(fields::PRIVATE_KEY_BIT_LENGTH, DataType::UInt16, false),
        Field::new(fields::PRIVATE_KEY_HAMMING_WEIGHT, DataType::UInt16, false),
        Field::new(fields::PRIVATE_KEY_LEADING_ZEROS, DataType::UInt8, false),
        // Public keys (nullable for non-Bitcoin chains)
        Field::new(fields::PUBKEY_COMPRESSED, DataType::Utf8, true),
        Field::new(fields::PUBKEY_UNCOMPRESSED, DataType::Utf8, true),
        // Addresses (nullable)
        Field::new(fields::ADDRESS_P2PKH_COMPRESSED, DataType::Utf8, true),
        Field::new(fields::ADDRESS_P2PKH_UNCOMPRESSED, DataType::Utf8, true),
        Field::new(fields::ADDRESS_P2WPKH, DataType::Utf8, true),
        // Export formats (nullable)
        Field::new(fields::WIF_COMPRESSED, DataType::Utf8, true),
        Field::new(fields::WIF_UNCOMPRESSED, DataType::Utf8, true),
    ])
}

/// Find a public key by format.
fn find_pubkey<'a>(records: &'a [PublicKeyRecord<'a>], format: &str) -> Option<&'a str> {
    records
        .iter()
        .find(|pk| pk.format == format)
        .map(|pk| pk.value)
}

/// Find an address by type.
fn find_address<'a>(records: &'a [AddressRecord<'a>], addr_type: &str) -> Option<&'a str> {
    records
        .iter()
        .find(|addr| addr.address_type == addr_type)
        .map(|addr| addr.address)
}

/// Find an export format by name.
fn find_export<'a>(records: &'a [ExportFormatRecord<'a>], format: &str) -> Option<&'a str> {
    records
        .iter()
        .find(|ef| ef.format == format)
        .map(|ef| ef.value)
}

/// Convert a batch of ResultRecords to an Arrow RecordBatch.
///
/// # Arguments
///
/// * `records` - Slice of ResultRecords to convert
///
/// # Returns
///
/// Arrow RecordBatch with the schema from `result_schema()`.
///
/// # Errors
///
/// Returns `ArrowError` if array construction fails.
pub fn records_to_batch(records: &[ResultRecord<'_>]) -> Result<RecordBatch, ArrowError> {
    let schema = Arc::new(result_schema());

    // Core metadata arrays
    let source_array: ArrayRef = Arc::new(StringArray::from_iter_values(
        records.iter().map(|r| r.source),
    ));
    let transform_array: ArrayRef = Arc::new(StringArray::from_iter_values(
        records.iter().map(|r| r.transform),
    ));
    let chain_array: ArrayRef = Arc::new(StringArray::from_iter_values(
        records.iter().map(|r| r.chain),
    ));
    let timestamp_array: ArrayRef = Arc::new(
        TimestampMillisecondArray::from_iter_values(
            records.iter().map(|r| r.timestamp.timestamp_millis()),
        )
        .with_timezone("UTC"),
    );
    let matched_target_array: ArrayRef = Arc::new(StringArray::from(
        records.iter().map(|r| r.matched_target).collect::<Vec<_>>(),
    ));

    // Private key arrays
    let private_key_raw_array: ArrayRef = {
        let mut builder = FixedSizeBinaryBuilder::with_capacity(records.len(), 32);
        for r in records {
            builder.append_value(r.private_key.raw)?;
        }
        Arc::new(builder.finish())
    };
    let private_key_hex_array: ArrayRef = Arc::new(StringArray::from_iter_values(
        records.iter().map(|r| r.private_key.hex),
    ));
    let private_key_decimal_array: ArrayRef = Arc::new(StringArray::from_iter_values(
        records.iter().map(|r| r.private_key.decimal),
    ));
    let private_key_binary_array: ArrayRef = Arc::new(StringArray::from_iter_values(
        records.iter().map(|r| r.private_key.binary),
    ));
    let private_key_bit_length_array: ArrayRef = Arc::new(UInt16Array::from_iter_values(
        records.iter().map(|r| r.private_key.bit_length),
    ));
    let private_key_hamming_weight_array: ArrayRef = Arc::new(UInt16Array::from_iter_values(
        records.iter().map(|r| r.private_key.hamming_weight),
    ));
    let private_key_leading_zeros_array: ArrayRef = Arc::new(UInt8Array::from_iter_values(
        records.iter().map(|r| r.private_key.leading_zeros),
    ));

    // Public key arrays (nullable)
    let pubkey_compressed_array: ArrayRef = Arc::new(StringArray::from(
        records
            .iter()
            .map(|r| find_pubkey(r.public_keys, "compressed"))
            .collect::<Vec<_>>(),
    ));
    let pubkey_uncompressed_array: ArrayRef = Arc::new(StringArray::from(
        records
            .iter()
            .map(|r| find_pubkey(r.public_keys, "uncompressed"))
            .collect::<Vec<_>>(),
    ));

    // Address arrays (nullable)
    let address_p2pkh_compressed_array: ArrayRef = Arc::new(StringArray::from(
        records
            .iter()
            .map(|r| find_address(r.addresses, "p2pkh_compressed"))
            .collect::<Vec<_>>(),
    ));
    let address_p2pkh_uncompressed_array: ArrayRef = Arc::new(StringArray::from(
        records
            .iter()
            .map(|r| find_address(r.addresses, "p2pkh_uncompressed"))
            .collect::<Vec<_>>(),
    ));
    let address_p2wpkh_array: ArrayRef = Arc::new(StringArray::from(
        records
            .iter()
            .map(|r| find_address(r.addresses, "p2wpkh"))
            .collect::<Vec<_>>(),
    ));

    // Export format arrays (nullable)
    let wif_compressed_array: ArrayRef = Arc::new(StringArray::from(
        records
            .iter()
            .map(|r| find_export(r.export_formats, "wif_compressed"))
            .collect::<Vec<_>>(),
    ));
    let wif_uncompressed_array: ArrayRef = Arc::new(StringArray::from(
        records
            .iter()
            .map(|r| find_export(r.export_formats, "wif_uncompressed"))
            .collect::<Vec<_>>(),
    ));

    RecordBatch::try_new(
        schema,
        vec![
            source_array,
            transform_array,
            chain_array,
            timestamp_array,
            matched_target_array,
            private_key_raw_array,
            private_key_hex_array,
            private_key_decimal_array,
            private_key_binary_array,
            private_key_bit_length_array,
            private_key_hamming_weight_array,
            private_key_leading_zeros_array,
            pubkey_compressed_array,
            pubkey_uncompressed_array,
            address_p2pkh_compressed_array,
            address_p2pkh_uncompressed_array,
            address_p2wpkh_array,
            wif_compressed_array,
            wif_uncompressed_array,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::PrivateKeyRecord;
    use arrow::array::{Array, FixedSizeBinaryArray};
    use arrow::datatypes::DataType;

    #[test]
    fn schema_has_19_fields() {
        let schema = result_schema();
        assert_eq!(schema.fields().len(), 19);
    }

    #[test]
    fn schema_field_names() {
        let schema = result_schema();
        let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();

        assert_eq!(
            names,
            vec![
                "source",
                "transform",
                "chain",
                "timestamp",
                "matched_target",
                "private_key_raw",
                "private_key_hex",
                "private_key_decimal",
                "private_key_binary",
                "private_key_bit_length",
                "private_key_hamming_weight",
                "private_key_leading_zeros",
                "pubkey_compressed",
                "pubkey_uncompressed",
                "address_p2pkh_compressed",
                "address_p2pkh_uncompressed",
                "address_p2wpkh",
                "wif_compressed",
                "wif_uncompressed",
            ]
        );
    }

    #[test]
    fn schema_field_types() {
        let schema = result_schema();

        assert_eq!(schema.field(0).data_type(), &DataType::Utf8);
        assert_eq!(schema.field(1).data_type(), &DataType::Utf8);
        assert_eq!(schema.field(2).data_type(), &DataType::Utf8);
        assert!(matches!(
            schema.field(3).data_type(),
            DataType::Timestamp(TimeUnit::Millisecond, Some(_))
        ));
        assert_eq!(schema.field(4).data_type(), &DataType::Utf8);
        assert_eq!(schema.field(5).data_type(), &DataType::FixedSizeBinary(32));
        assert_eq!(schema.field(6).data_type(), &DataType::Utf8);
        assert_eq!(schema.field(7).data_type(), &DataType::Utf8);
        assert_eq!(schema.field(8).data_type(), &DataType::Utf8);
        assert_eq!(schema.field(9).data_type(), &DataType::UInt16);
        assert_eq!(schema.field(10).data_type(), &DataType::UInt16);
        assert_eq!(schema.field(11).data_type(), &DataType::UInt8);

        for i in 12..19 {
            assert_eq!(schema.field(i).data_type(), &DataType::Utf8);
        }
    }

    #[test]
    fn schema_nullable_flags() {
        let schema = result_schema();

        let non_nullable = [0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11];
        for i in non_nullable {
            assert!(
                !schema.field(i).is_nullable(),
                "field {} should be non-nullable",
                i
            );
        }

        let nullable = [4, 12, 13, 14, 15, 16, 17, 18];
        for i in nullable {
            assert!(
                schema.field(i).is_nullable(),
                "field {} should be nullable",
                i
            );
        }
    }

    #[test]
    fn records_to_batch_empty() {
        let batch = records_to_batch(&[]).unwrap();
        assert_eq!(batch.num_rows(), 0);
        assert_eq!(batch.num_columns(), 19);
        assert_eq!(batch.schema(), Arc::new(result_schema()));
    }

    fn make_test_record<'a>(
        raw: &'a [u8; 32],
        public_keys: &'a [PublicKeyRecord<'a>],
        addresses: &'a [AddressRecord<'a>],
        export_formats: &'a [ExportFormatRecord<'a>],
        matched_target: Option<&'a str>,
    ) -> ResultRecord<'a> {
        ResultRecord {
            source: "test_source",
            transform: "sha256",
            chain: "bitcoin",
            timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            private_key: PrivateKeyRecord {
                raw,
                hex: "0101010101010101010101010101010101010101010101010101010101010101",
                decimal:
                    "454086624460063511464984254936031011189294057512315937409637584344757371137",
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
    fn records_to_batch_single_record() {
        let raw = [1u8; 32];
        let public_keys = [
            PublicKeyRecord {
                format: "compressed",
                value: "02abc123",
            },
            PublicKeyRecord {
                format: "uncompressed",
                value: "04abc123def456",
            },
        ];
        let addresses = [
            AddressRecord {
                address_type: "p2pkh_compressed",
                address: "1ABC123",
            },
            AddressRecord {
                address_type: "p2pkh_uncompressed",
                address: "1DEF456",
            },
            AddressRecord {
                address_type: "p2wpkh",
                address: "bc1qtest",
            },
        ];
        let export_formats = [
            ExportFormatRecord {
                format: "wif_compressed",
                value: "L1234",
            },
            ExportFormatRecord {
                format: "wif_uncompressed",
                value: "5J1234",
            },
        ];

        let record = make_test_record(&raw, &public_keys, &addresses, &export_formats, None);
        let batch = records_to_batch(&[record]).unwrap();

        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.num_columns(), 19);

        let source_col = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(source_col.value(0), "test_source");

        let transform_col = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(transform_col.value(0), "sha256");

        let chain_col = batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(chain_col.value(0), "bitcoin");

        let pk_raw_col = batch
            .column(5)
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .unwrap();
        assert_eq!(pk_raw_col.value(0), &[1u8; 32]);

        let pk_bit_length_col = batch
            .column(9)
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap();
        assert_eq!(pk_bit_length_col.value(0), 249);

        let pubkey_compressed_col = batch
            .column(12)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(pubkey_compressed_col.value(0), "02abc123");

        let addr_p2wpkh_col = batch
            .column(16)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(addr_p2wpkh_col.value(0), "bc1qtest");

        let wif_compressed_col = batch
            .column(17)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(wif_compressed_col.value(0), "L1234");
    }

    #[test]
    fn records_to_batch_with_matched_target() {
        let raw = [1u8; 32];
        let record = make_test_record(&raw, &[], &[], &[], Some("1MatchedAddress"));
        let batch = records_to_batch(&[record]).unwrap();

        let matched_col = batch
            .column(4)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(!matched_col.is_null(0));
        assert_eq!(matched_col.value(0), "1MatchedAddress");
    }

    #[test]
    fn records_to_batch_with_none_matched_target() {
        let raw = [1u8; 32];
        let record = make_test_record(&raw, &[], &[], &[], None);
        let batch = records_to_batch(&[record]).unwrap();

        let matched_col = batch
            .column(4)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(matched_col.is_null(0));
    }

    #[test]
    fn records_to_batch_empty_slices() {
        let raw = [0u8; 32];
        let record = make_test_record(&raw, &[], &[], &[], None);
        let batch = records_to_batch(&[record]).unwrap();

        let pubkey_compressed = batch
            .column(12)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(pubkey_compressed.is_null(0));

        let addr_p2pkh = batch
            .column(14)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(addr_p2pkh.is_null(0));

        let wif = batch
            .column(17)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(wif.is_null(0));
    }

    #[test]
    fn records_to_batch_multiple_records() {
        let raw1 = [1u8; 32];
        let raw2 = [2u8; 32];
        let raw3 = [3u8; 32];

        let record1 = make_test_record(&raw1, &[], &[], &[], None);
        let mut record2 = make_test_record(&raw2, &[], &[], &[], Some("matched"));
        record2.source = "source2";
        record2.transform = "milksad";
        let mut record3 = make_test_record(&raw3, &[], &[], &[], None);
        record3.source = "source3";
        record3.chain = "ethereum";

        let batch = records_to_batch(&[record1, record2, record3]).unwrap();

        assert_eq!(batch.num_rows(), 3);

        let source_col = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(source_col.value(0), "test_source");
        assert_eq!(source_col.value(1), "source2");
        assert_eq!(source_col.value(2), "source3");

        let transform_col = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(transform_col.value(0), "sha256");
        assert_eq!(transform_col.value(1), "milksad");
        assert_eq!(transform_col.value(2), "sha256");

        let chain_col = batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(chain_col.value(0), "bitcoin");
        assert_eq!(chain_col.value(1), "bitcoin");
        assert_eq!(chain_col.value(2), "ethereum");

        let matched_col = batch
            .column(4)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(matched_col.is_null(0));
        assert!(!matched_col.is_null(1));
        assert_eq!(matched_col.value(1), "matched");
        assert!(matched_col.is_null(2));
    }

    #[test]
    fn find_pubkey_works() {
        let pubkeys = [
            PublicKeyRecord {
                format: "compressed",
                value: "02abc",
            },
            PublicKeyRecord {
                format: "uncompressed",
                value: "04def",
            },
        ];

        assert_eq!(find_pubkey(&pubkeys, "compressed"), Some("02abc"));
        assert_eq!(find_pubkey(&pubkeys, "uncompressed"), Some("04def"));
        assert_eq!(find_pubkey(&pubkeys, "ed25519"), None);
        assert_eq!(find_pubkey(&[], "compressed"), None);
    }

    #[test]
    fn find_address_works() {
        let addresses = [
            AddressRecord {
                address_type: "p2pkh_compressed",
                address: "1ABC",
            },
            AddressRecord {
                address_type: "p2wpkh",
                address: "bc1q",
            },
        ];

        assert_eq!(find_address(&addresses, "p2pkh_compressed"), Some("1ABC"));
        assert_eq!(find_address(&addresses, "p2wpkh"), Some("bc1q"));
        assert_eq!(find_address(&addresses, "p2sh"), None);
        assert_eq!(find_address(&[], "p2pkh"), None);
    }

    #[test]
    fn find_export_works() {
        let exports = [
            ExportFormatRecord {
                format: "wif_compressed",
                value: "L123",
            },
            ExportFormatRecord {
                format: "wif_uncompressed",
                value: "5J123",
            },
        ];

        assert_eq!(find_export(&exports, "wif_compressed"), Some("L123"));
        assert_eq!(find_export(&exports, "wif_uncompressed"), Some("5J123"));
        assert_eq!(find_export(&exports, "hex"), None);
        assert_eq!(find_export(&[], "wif_compressed"), None);
    }
}
