mod catalog;
mod error;
mod partition;
mod schema;

pub use catalog::RestCatalogClient;
pub use error::{IcebergError, Result};
pub use partition::build_partition_spec;
pub use schema::{build_iceberg_schema, timestamp_field_id, transform_field_id};

#[derive(Debug, Clone)]
pub struct IcebergConfig {
    pub catalog_url: String,
    pub namespace: String,
    pub table_name: String,
}

impl IcebergConfig {
    pub fn new(catalog_url: impl Into<String>) -> Self {
        Self {
            catalog_url: catalog_url.into(),
            namespace: "vuke".to_string(),
            table_name: "results".to_string(),
        }
    }

    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    pub fn with_table_name(mut self, table_name: impl Into<String>) -> Self {
        self.table_name = table_name.into();
        self
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub snapshot_id: i64,
    pub files_registered: usize,
}

/// Metadata about a Parquet file to register with Iceberg
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// Cloud URI (e.g., s3://bucket/path/file.parquet)
    pub uri: String,
    /// File size in bytes
    pub file_size: u64,
    /// Number of records in the file
    pub record_count: u64,
    /// Partition values extracted from Hive-style path
    pub partition_values: Option<PartitionValues>,
}

/// Partition values for Iceberg table (transform and timestamp_day)
#[derive(Debug, Clone)]
pub struct PartitionValues {
    /// Transform name (identity partition)
    pub transform: String,
    /// Timestamp day (days since epoch for day partition)
    pub timestamp_day: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_new_with_defaults() {
        let config = IcebergConfig::new("http://localhost:8181");
        assert_eq!(config.catalog_url, "http://localhost:8181");
        assert_eq!(config.namespace, "vuke");
        assert_eq!(config.table_name, "results");
    }

    #[test]
    fn config_builder_pattern() {
        let config = IcebergConfig::new("http://localhost:8181")
            .with_namespace("custom_ns")
            .with_table_name("custom_table");

        assert_eq!(config.namespace, "custom_ns");
        assert_eq!(config.table_name, "custom_table");
    }
}
