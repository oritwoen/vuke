mod credentials;
pub mod error;
pub mod progress;
mod s3;
mod sync;

pub use credentials::CloudCredentials;
pub use error::{CloudError, Result};
pub use progress::{NoOpProgress, StatsProgress, UploadProgress, UploadStats};
pub use s3::S3CloudUploader;
pub use sync::{sync_to_cloud_blocking, BatchUploader, CloudSyncManager, SyncResult};

use async_trait::async_trait;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct CloudConfig {
    pub endpoint: Option<String>,
    pub bucket: String,
    pub prefix: Option<String>,
    pub delete_local: bool,
    pub max_retries: u32,
    pub base_retry_delay: Duration,
    pub max_retry_delay: Duration,
    pub fail_fast: bool,
}

impl CloudConfig {
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            endpoint: None,
            bucket: bucket.into(),
            prefix: None,
            delete_local: false,
            max_retries: 5,
            base_retry_delay: Duration::from_millis(100),
            max_retry_delay: Duration::from_secs(30),
            fail_fast: false,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub fn with_delete_local(mut self, delete: bool) -> Self {
        self.delete_local = delete;
        self
    }

    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    pub fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }
}

#[derive(Debug, Clone)]
pub struct CloudPath {
    pub bucket: String,
    pub key: String,
}

impl CloudPath {
    pub fn new(bucket: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            key: key.into(),
        }
    }

    pub fn url(&self, endpoint: Option<&str>) -> String {
        match endpoint {
            Some(ep) => format!("{}/{}/{}", ep.trim_end_matches('/'), self.bucket, self.key),
            None => format!("s3://{}/{}", self.bucket, self.key),
        }
    }
}

#[async_trait]
pub trait CloudUploader: Send + Sync {
    async fn upload_file(&self, local_path: &Path) -> Result<CloudPath>;

    async fn list_objects(&self, prefix: Option<&str>) -> Result<Vec<CloudPath>>;

    fn bucket(&self) -> &str;

    fn endpoint(&self) -> Option<&str>;

    fn config(&self) -> &CloudConfig;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_config_defaults() {
        let config = CloudConfig::new("test-bucket");
        assert_eq!(config.bucket, "test-bucket");
        assert!(config.endpoint.is_none());
        assert!(config.prefix.is_none());
        assert!(!config.delete_local);
        assert_eq!(config.max_retries, 5);
        assert!(!config.fail_fast);
    }

    #[test]
    fn cloud_config_builder() {
        let config = CloudConfig::new("my-bucket")
            .with_endpoint("https://s3.example.com")
            .with_prefix("vuke/results")
            .with_delete_local(true)
            .with_max_retries(3)
            .with_fail_fast(true);

        assert_eq!(config.bucket, "my-bucket");
        assert_eq!(config.endpoint.as_deref(), Some("https://s3.example.com"));
        assert_eq!(config.prefix.as_deref(), Some("vuke/results"));
        assert!(config.delete_local);
        assert_eq!(config.max_retries, 3);
        assert!(config.fail_fast);
    }

    #[test]
    fn cloud_path_url_with_endpoint() {
        let path = CloudPath::new("bucket", "path/to/file.parquet");
        assert_eq!(
            path.url(Some("https://r2.example.com")),
            "https://r2.example.com/bucket/path/to/file.parquet"
        );
    }

    #[test]
    fn cloud_path_url_without_endpoint() {
        let path = CloudPath::new("bucket", "file.parquet");
        assert_eq!(path.url(None), "s3://bucket/file.parquet");
    }

    #[test]
    fn cloud_path_url_strips_trailing_slash() {
        let path = CloudPath::new("bucket", "file.parquet");
        assert_eq!(
            path.url(Some("https://example.com/")),
            "https://example.com/bucket/file.parquet"
        );
    }
}
