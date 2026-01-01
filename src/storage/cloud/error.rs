use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum CloudError {
    NoCredentials,
    InvalidEndpoint(String),
    InvalidBucket(String),
    ConnectionFailed(String),
    UploadFailed {
        path: PathBuf,
        cause: String,
    },
    RetryExhausted {
        path: PathBuf,
        attempts: u32,
        last_error: String,
    },
    ObjectStore(object_store::Error),
    Io(std::io::Error),
}

impl fmt::Display for CloudError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudError::NoCredentials => {
                write!(f, "No cloud credentials found. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
            }
            CloudError::InvalidEndpoint(endpoint) => {
                write!(f, "Invalid cloud endpoint: {}", endpoint)
            }
            CloudError::InvalidBucket(bucket) => {
                write!(f, "Invalid bucket name: {}", bucket)
            }
            CloudError::ConnectionFailed(reason) => {
                write!(f, "Cloud connection failed: {}", reason)
            }
            CloudError::UploadFailed { path, cause } => {
                write!(f, "Upload failed for {}: {}", path.display(), cause)
            }
            CloudError::RetryExhausted {
                path,
                attempts,
                last_error,
            } => {
                write!(
                    f,
                    "Upload failed for {} after {} attempts: {}",
                    path.display(),
                    attempts,
                    last_error
                )
            }
            CloudError::ObjectStore(e) => write!(f, "Object store error: {}", e),
            CloudError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for CloudError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CloudError::ObjectStore(e) => Some(e),
            CloudError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<object_store::Error> for CloudError {
    fn from(err: object_store::Error) -> Self {
        CloudError::ObjectStore(err)
    }
}

impl From<std::io::Error> for CloudError {
    fn from(err: std::io::Error) -> Self {
        CloudError::Io(err)
    }
}

pub type Result<T> = std::result::Result<T, CloudError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_no_credentials() {
        let err = CloudError::NoCredentials;
        assert!(err.to_string().contains("AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn error_display_invalid_endpoint() {
        let err = CloudError::InvalidEndpoint("not-a-url".to_string());
        assert!(err.to_string().contains("not-a-url"));
    }

    #[test]
    fn error_display_retry_exhausted() {
        let err = CloudError::RetryExhausted {
            path: PathBuf::from("/tmp/test.parquet"),
            attempts: 5,
            last_error: "connection refused".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("5 attempts"));
        assert!(msg.contains("test.parquet"));
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let cloud_err: CloudError = io_err.into();
        assert!(matches!(cloud_err, CloudError::Io(_)));
    }
}
