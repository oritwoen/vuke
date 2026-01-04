use iceberg::spec::{NestedField, PrimitiveType, Schema as IcebergSchema, Type};

use super::error::{IcebergError, Result};
use crate::storage::schema::fields;

pub fn build_iceberg_schema() -> Result<IcebergSchema> {
    let mut field_id = 1;
    let mut next_id = || {
        let id = field_id;
        field_id += 1;
        id
    };

    let fields = vec![
        NestedField::required(
            next_id(),
            fields::SOURCE,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::required(
            next_id(),
            fields::TRANSFORM,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::required(
            next_id(),
            fields::CHAIN,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::required(
            next_id(),
            fields::TIMESTAMP,
            Type::Primitive(PrimitiveType::Timestamptz),
        )
        .into(),
        NestedField::optional(
            next_id(),
            fields::MATCHED_TARGET,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::required(
            next_id(),
            fields::PRIVATE_KEY_RAW,
            Type::Primitive(PrimitiveType::Fixed(32)),
        )
        .into(),
        NestedField::required(
            next_id(),
            fields::PRIVATE_KEY_HEX,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::required(
            next_id(),
            fields::PRIVATE_KEY_DECIMAL,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::required(
            next_id(),
            fields::PRIVATE_KEY_BINARY,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::required(
            next_id(),
            fields::PRIVATE_KEY_BIT_LENGTH,
            Type::Primitive(PrimitiveType::Int),
        )
        .into(),
        NestedField::required(
            next_id(),
            fields::PRIVATE_KEY_HAMMING_WEIGHT,
            Type::Primitive(PrimitiveType::Int),
        )
        .into(),
        NestedField::required(
            next_id(),
            fields::PRIVATE_KEY_LEADING_ZEROS,
            Type::Primitive(PrimitiveType::Int),
        )
        .into(),
        NestedField::optional(
            next_id(),
            fields::PUBKEY_COMPRESSED,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::optional(
            next_id(),
            fields::PUBKEY_UNCOMPRESSED,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::optional(
            next_id(),
            fields::ADDRESS_P2PKH_COMPRESSED,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::optional(
            next_id(),
            fields::ADDRESS_P2PKH_UNCOMPRESSED,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::optional(
            next_id(),
            fields::ADDRESS_P2WPKH,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::optional(
            next_id(),
            fields::WIF_COMPRESSED,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
        NestedField::optional(
            next_id(),
            fields::WIF_UNCOMPRESSED,
            Type::Primitive(PrimitiveType::String),
        )
        .into(),
    ];

    IcebergSchema::builder()
        .with_fields(fields)
        .with_schema_id(1)
        .build()
        .map_err(|e| IcebergError::SchemaConversion(e.to_string()))
}

pub fn transform_field_id() -> i32 {
    2
}

pub fn timestamp_field_id() -> i32 {
    4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_schema_succeeds() {
        let schema = build_iceberg_schema().unwrap();
        assert_eq!(schema.as_struct().fields().len(), 19);
    }

    #[test]
    fn schema_has_correct_field_names() {
        let schema = build_iceberg_schema().unwrap();
        let struct_type = schema.as_struct();

        assert!(struct_type.field_by_name("source").is_some());
        assert!(struct_type.field_by_name("transform").is_some());
        assert!(struct_type.field_by_name("timestamp").is_some());
        assert!(struct_type.field_by_name("private_key_raw").is_some());
        assert!(struct_type.field_by_name("address_p2wpkh").is_some());
    }

    #[test]
    fn schema_required_fields_are_not_nullable() {
        let schema = build_iceberg_schema().unwrap();
        let struct_type = schema.as_struct();

        let source_field = struct_type.field_by_name("source").unwrap();
        assert!(source_field.required);

        let transform_field = struct_type.field_by_name("transform").unwrap();
        assert!(transform_field.required);
    }

    #[test]
    fn schema_optional_fields_are_nullable() {
        let schema = build_iceberg_schema().unwrap();
        let struct_type = schema.as_struct();

        let matched_target = struct_type.field_by_name("matched_target").unwrap();
        assert!(!matched_target.required);

        let wif_compressed = struct_type.field_by_name("wif_compressed").unwrap();
        assert!(!wif_compressed.required);
    }

    #[test]
    fn schema_private_key_raw_is_fixed_32() {
        let schema = build_iceberg_schema().unwrap();
        let struct_type = schema.as_struct();

        let pk_raw = struct_type.field_by_name("private_key_raw").unwrap();

        match pk_raw.field_type.as_ref() {
            Type::Primitive(PrimitiveType::Fixed(size)) => assert_eq!(*size, 32),
            other => panic!("expected Fixed(32), got {:?}", other),
        }
    }

    #[test]
    fn schema_timestamp_is_timestamptz() {
        let schema = build_iceberg_schema().unwrap();
        let struct_type = schema.as_struct();

        let ts = struct_type.field_by_name("timestamp").unwrap();

        assert!(matches!(
            ts.field_type.as_ref(),
            Type::Primitive(PrimitiveType::Timestamptz)
        ));
    }

    #[test]
    fn field_ids_are_sequential() {
        let schema = build_iceberg_schema().unwrap();
        let fields = schema.as_struct().fields();
        let ids: Vec<i32> = fields.iter().map(|f| f.id).collect();

        for (i, id) in ids.iter().enumerate() {
            assert_eq!(*id, (i + 1) as i32);
        }
    }

    #[test]
    fn transform_field_id_is_correct() {
        let schema = build_iceberg_schema().unwrap();
        let transform = schema.as_struct().field_by_name("transform").unwrap();
        assert_eq!(transform.id, transform_field_id());
    }

    #[test]
    fn timestamp_field_id_is_correct() {
        let schema = build_iceberg_schema().unwrap();
        let timestamp = schema.as_struct().field_by_name("timestamp").unwrap();
        assert_eq!(timestamp.id, timestamp_field_id());
    }
}
