use iceberg::spec::{Transform, UnboundPartitionSpec};

use super::error::IcebergError;
use super::schema::{timestamp_field_id, transform_field_id};

pub fn build_partition_spec() -> Result<UnboundPartitionSpec, IcebergError> {
    Ok(UnboundPartitionSpec::builder()
        .add_partition_field(transform_field_id(), "transform", Transform::Identity)
        .map_err(|e| IcebergError::SchemaConversion(format!("transform partition: {e}")))?
        .add_partition_field(timestamp_field_id(), "timestamp_day", Transform::Day)
        .map_err(|e| IcebergError::SchemaConversion(format!("timestamp partition: {e}")))?
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_partition_spec_succeeds() {
        let spec = build_partition_spec().unwrap();
        assert_eq!(spec.fields().len(), 2);
    }

    #[test]
    fn partition_spec_has_transform_identity() {
        let spec = build_partition_spec().unwrap();
        let transform_field = &spec.fields()[0];

        assert_eq!(transform_field.name, "transform");
        assert_eq!(transform_field.source_id, transform_field_id());
        assert!(matches!(transform_field.transform, Transform::Identity));
    }

    #[test]
    fn partition_spec_has_timestamp_day() {
        let spec = build_partition_spec().unwrap();
        let timestamp_field = &spec.fields()[1];

        assert_eq!(timestamp_field.name, "timestamp_day");
        assert_eq!(timestamp_field.source_id, timestamp_field_id());
        assert!(matches!(timestamp_field.transform, Transform::Day));
    }

    #[test]
    fn partition_spec_field_ids_are_unbound() {
        let spec = build_partition_spec().unwrap();

        for field in spec.fields() {
            assert!(field.field_id.is_none());
        }
    }
}
