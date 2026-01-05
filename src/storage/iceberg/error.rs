use std::fmt;

pub type Result<T> = std::result::Result<T, IcebergError>;

#[derive(Debug)]
pub enum IcebergError {
    CatalogConnection(String),
    SchemaConversion(String),
    SnapshotCommit(String),
    NamespaceCreation(String),
    TableCreation(String),
    TableLoad(String),
    DataFileRegistration(String),
    InvalidConfig(String),
    Credentials(crate::storage::CloudError),
    Io(std::io::Error),
    Iceberg(iceberg::Error),
}

impl fmt::Display for IcebergError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CatalogConnection(msg) => write!(f, "catalog connection failed: {}", msg),
            Self::SchemaConversion(msg) => write!(f, "schema conversion failed: {}", msg),
            Self::SnapshotCommit(msg) => write!(f, "snapshot commit failed: {}", msg),
            Self::NamespaceCreation(msg) => write!(f, "namespace creation failed: {}", msg),
            Self::TableCreation(msg) => write!(f, "table creation failed: {}", msg),
            Self::TableLoad(msg) => write!(f, "table load failed: {}", msg),
            Self::DataFileRegistration(msg) => write!(f, "data file registration failed: {}", msg),
            Self::InvalidConfig(msg) => write!(f, "invalid configuration: {}", msg),
            Self::Credentials(e) => write!(f, "credentials error: {}", e),
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Iceberg(e) => write!(f, "iceberg error: {}", e),
        }
    }
}

impl std::error::Error for IcebergError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Credentials(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Iceberg(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for IcebergError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<iceberg::Error> for IcebergError {
    fn from(err: iceberg::Error) -> Self {
        Self::Iceberg(err)
    }
}

impl From<crate::storage::CloudError> for IcebergError {
    fn from(err: crate::storage::CloudError) -> Self {
        Self::Credentials(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn error_display_catalog_connection() {
        let err = IcebergError::CatalogConnection("connection refused".to_string());
        assert!(err.to_string().contains("catalog connection failed"));
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn error_display_schema_conversion() {
        let err = IcebergError::SchemaConversion("unsupported type".to_string());
        assert!(err.to_string().contains("schema conversion failed"));
    }

    #[test]
    fn error_display_invalid_config() {
        let err = IcebergError::InvalidConfig("missing catalog URL".to_string());
        assert!(err.to_string().contains("invalid configuration"));
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: IcebergError = io_err.into();
        assert!(matches!(err, IcebergError::Io(_)));
        assert!(err.source().is_some());
    }
}
