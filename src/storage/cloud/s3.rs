use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, WriteMultipart};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use super::error::{CloudError, Result};
use super::progress::UploadProgress;
use super::{CloudConfig, CloudPath, CloudUploader};

pub struct S3CloudUploader {
    store: Arc<dyn ObjectStore>,
    config: CloudConfig,
    progress: Arc<dyn UploadProgress>,
}

impl S3CloudUploader {
    pub fn new(config: CloudConfig, progress: Arc<dyn UploadProgress>) -> Result<Self> {
        let store = Self::build_store(&config)?;
        Ok(Self {
            store,
            config,
            progress,
        })
    }

    pub fn from_env(
        bucket: impl Into<String>,
        progress: Arc<dyn UploadProgress>,
    ) -> Result<Self> {
        let config = CloudConfig::new(bucket);
        Self::new(config, progress)
    }

    fn build_store(config: &CloudConfig) -> Result<Arc<dyn ObjectStore>> {
        let mut builder = AmazonS3Builder::from_env().with_bucket_name(&config.bucket);

        if let Some(ref endpoint) = config.endpoint {
            builder = builder.with_endpoint(endpoint);
            builder = builder.with_virtual_hosted_style_request(false);
        }

        let store = builder.build().map_err(|e| {
            if e.to_string().contains("Missing") || e.to_string().contains("credential") {
                CloudError::NoCredentials
            } else if e.to_string().contains("endpoint") {
                CloudError::InvalidEndpoint(config.endpoint.clone().unwrap_or_default())
            } else {
                CloudError::from(e)
            }
        })?;

        Ok(Arc::new(store))
    }

    fn compute_remote_key(&self, local_path: &Path) -> String {
        let file_name = local_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("chunk.parquet");

        let parent_components: Vec<&str> = local_path
            .parent()
            .map(|p| {
                p.components()
                    .filter_map(|c| c.as_os_str().to_str())
                    .filter(|s| s.starts_with("transform=") || s.starts_with("date="))
                    .collect()
            })
            .unwrap_or_default();

        let mut key_parts = Vec::new();

        if let Some(ref prefix) = self.config.prefix {
            key_parts.push(prefix.trim_matches('/').to_string());
        }

        key_parts.extend(parent_components.into_iter().map(String::from));
        key_parts.push(file_name.to_string());

        key_parts.join("/")
    }

    async fn upload_with_retry(&self, local_path: &Path) -> Result<CloudPath> {
        let file_size = tokio::fs::metadata(local_path).await?.len();
        self.progress.on_upload_start(local_path, file_size);

        let start = Instant::now();
        let mut last_error = String::new();

        for attempt in 1..=self.config.max_retries {
            match self.do_upload(local_path).await {
                Ok(cloud_path) => {
                    self.progress
                        .on_upload_complete(local_path, start.elapsed());
                    return Ok(cloud_path);
                }
                Err(e) => {
                    last_error = e.to_string();

                    if attempt < self.config.max_retries {
                        self.progress
                            .on_retry(local_path, attempt, self.config.max_retries);
                        let delay = self.compute_retry_delay(attempt);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        let error = CloudError::RetryExhausted {
            path: local_path.to_path_buf(),
            attempts: self.config.max_retries,
            last_error,
        };
        self.progress.on_upload_error(local_path, &error);
        Err(error)
    }

    fn compute_retry_delay(&self, attempt: u32) -> Duration {
        let base_ms = self.config.base_retry_delay.as_millis() as u64;
        let exponential_ms = base_ms * 2u64.pow(attempt - 1);

        let jitter_range = exponential_ms / 5;
        let jitter = if jitter_range > 0 {
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64)
                % (jitter_range * 2)
        } else {
            0
        };
        let jittered_ms = exponential_ms.saturating_sub(jitter_range).saturating_add(jitter);

        Duration::from_millis(jittered_ms.min(self.config.max_retry_delay.as_millis() as u64))
    }

    async fn do_upload(&self, local_path: &Path) -> Result<CloudPath> {
        let mut file = File::open(local_path).await?;
        let remote_key = self.compute_remote_key(local_path);
        let object_path = ObjectPath::from(remote_key.clone());

        let upload = self.store.put_multipart(&object_path).await?;
        let mut writer = WriteMultipart::new(upload);

        let mut buf = vec![0u8; 8 * 1024 * 1024];
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            writer.write(&buf[..n]);
        }

        writer.finish().await?;

        Ok(CloudPath::new(&self.config.bucket, remote_key))
    }
}

#[async_trait]
impl CloudUploader for S3CloudUploader {
    async fn upload_file(&self, local_path: &Path) -> Result<CloudPath> {
        self.upload_with_retry(local_path).await
    }

    async fn list_objects(&self, prefix: Option<&str>) -> Result<Vec<CloudPath>> {
        use futures::TryStreamExt;

        let prefix_path = prefix.map(ObjectPath::from);

        let list_result = match prefix_path {
            Some(p) => self.store.list(Some(&p)),
            None => self.store.list(None),
        };

        let objects: Vec<_> = list_result.try_collect().await?;

        Ok(objects
            .into_iter()
            .map(|meta| CloudPath::new(&self.config.bucket, meta.location.to_string()))
            .collect())
    }

    fn bucket(&self) -> &str {
        &self.config.bucket
    }

    fn endpoint(&self) -> Option<&str> {
        self.config.endpoint.as_deref()
    }

    fn config(&self) -> &CloudConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::cloud::progress::NoOpProgress;
    use std::path::PathBuf;

    fn test_config() -> CloudConfig {
        CloudConfig::new("test-bucket")
            .with_endpoint("http://localhost:9000")
            .with_prefix("vuke/test")
    }

    #[test]
    fn compute_remote_key_simple() {
        let config = test_config();
        let progress = Arc::new(NoOpProgress);
        
        let uploader = S3CloudUploader {
            store: Arc::new(object_store::memory::InMemory::new()),
            config,
            progress,
        };

        let path = PathBuf::from("/tmp/results/chunk_0001.parquet");
        let key = uploader.compute_remote_key(&path);
        assert_eq!(key, "vuke/test/chunk_0001.parquet");
    }

    #[test]
    fn compute_remote_key_with_partitions() {
        let config = test_config();
        let progress = Arc::new(NoOpProgress);

        let uploader = S3CloudUploader {
            store: Arc::new(object_store::memory::InMemory::new()),
            config,
            progress,
        };

        let path =
            PathBuf::from("/tmp/results/transform=milksad/date=2025-01-01/chunk_0001.parquet");
        let key = uploader.compute_remote_key(&path);
        assert_eq!(
            key,
            "vuke/test/transform=milksad/date=2025-01-01/chunk_0001.parquet"
        );
    }

    #[test]
    fn compute_remote_key_no_prefix() {
        let config = CloudConfig::new("bucket");
        let progress = Arc::new(NoOpProgress);

        let uploader = S3CloudUploader {
            store: Arc::new(object_store::memory::InMemory::new()),
            config,
            progress,
        };

        let path = PathBuf::from("/results/transform=sha256/chunk_0001.parquet");
        let key = uploader.compute_remote_key(&path);
        assert_eq!(key, "transform=sha256/chunk_0001.parquet");
    }

    #[test]
    fn compute_retry_delay_exponential() {
        let config = CloudConfig::new("bucket");
        let progress = Arc::new(NoOpProgress);

        let uploader = S3CloudUploader {
            store: Arc::new(object_store::memory::InMemory::new()),
            config,
            progress,
        };

        let delay1 = uploader.compute_retry_delay(1);
        let delay2 = uploader.compute_retry_delay(2);
        let delay3 = uploader.compute_retry_delay(3);

        assert!(delay1.as_millis() >= 80 && delay1.as_millis() <= 120);
        assert!(delay2.as_millis() >= 160 && delay2.as_millis() <= 240);
        assert!(delay3.as_millis() >= 320 && delay3.as_millis() <= 480);
    }

    #[test]
    fn compute_retry_delay_capped_at_max() {
        let config = CloudConfig::new("bucket");
        let progress = Arc::new(NoOpProgress);

        let uploader = S3CloudUploader {
            store: Arc::new(object_store::memory::InMemory::new()),
            config,
            progress,
        };

        let delay = uploader.compute_retry_delay(20);
        assert!(delay <= Duration::from_secs(30));
    }

    #[tokio::test]
    async fn upload_to_memory_store() {
        let config = CloudConfig::new("test-bucket").with_prefix("test");
        let progress = Arc::new(NoOpProgress);
        let store = Arc::new(object_store::memory::InMemory::new());

        let uploader = S3CloudUploader {
            store: store.clone(),
            config,
            progress,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("chunk_0001.parquet");
        std::fs::write(&file_path, b"test data").unwrap();

        let result = uploader.upload_file(&file_path).await;
        assert!(result.is_ok());

        let cloud_path = result.unwrap();
        assert_eq!(cloud_path.bucket, "test-bucket");
        assert!(cloud_path.key.contains("chunk_0001.parquet"));

        let object_path = ObjectPath::from(cloud_path.key);
        let retrieved = store.get(&object_path).await.unwrap();
        let bytes = retrieved.bytes().await.unwrap();
        assert_eq!(&bytes[..], b"test data");
    }

    #[tokio::test]
    async fn list_objects_empty() {
        let config = CloudConfig::new("test-bucket");
        let progress = Arc::new(NoOpProgress);
        let store = Arc::new(object_store::memory::InMemory::new());

        let uploader = S3CloudUploader {
            store,
            config,
            progress,
        };

        let objects = uploader.list_objects(None).await.unwrap();
        assert!(objects.is_empty());
    }

    #[tokio::test]
    async fn list_objects_after_upload() {
        let config = CloudConfig::new("test-bucket");
        let progress = Arc::new(NoOpProgress);
        let store = Arc::new(object_store::memory::InMemory::new());

        let uploader = S3CloudUploader {
            store: store.clone(),
            config,
            progress,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let file1 = temp_dir.path().join("file1.parquet");
        let file2 = temp_dir.path().join("file2.parquet");
        std::fs::write(&file1, b"data1").unwrap();
        std::fs::write(&file2, b"data2").unwrap();

        uploader.upload_file(&file1).await.unwrap();
        uploader.upload_file(&file2).await.unwrap();

        let objects = uploader.list_objects(None).await.unwrap();
        assert_eq!(objects.len(), 2);
    }
}
