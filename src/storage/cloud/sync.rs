use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::error::{CloudError, Result};
use super::{CloudConfig, CloudPath, CloudUploader};

pub struct CloudSyncManager {
    uploader: Arc<dyn CloudUploader>,
    pending_uploads: Vec<JoinHandle<Result<CloudPath>>>,
    completed: Vec<CloudPath>,
    failed: Vec<(PathBuf, CloudError)>,
}

impl CloudSyncManager {
    pub fn new(uploader: Arc<dyn CloudUploader>) -> Self {
        Self {
            uploader,
            pending_uploads: Vec::new(),
            completed: Vec::new(),
            failed: Vec::new(),
        }
    }

    pub fn spawn_upload(&mut self, local_path: PathBuf) {
        let uploader = self.uploader.clone();
        let handle = tokio::spawn(async move { uploader.upload_file(&local_path).await });
        self.pending_uploads.push(handle);
    }

    pub async fn wait_for_all(&mut self) -> SyncResult {
        let handles = std::mem::take(&mut self.pending_uploads);

        for handle in handles {
            match handle.await {
                Ok(Ok(cloud_path)) => {
                    self.completed.push(cloud_path);
                }
                Ok(Err(e)) => {
                    let path = match &e {
                        CloudError::UploadFailed { path, .. } => path.clone(),
                        CloudError::RetryExhausted { path, .. } => path.clone(),
                        _ => PathBuf::new(),
                    };
                    self.failed.push((path, e));
                }
                Err(join_error) => {
                    self.failed.push((
                        PathBuf::new(),
                        CloudError::UploadFailed {
                            path: PathBuf::new(),
                            cause: format!("Task panicked: {}", join_error),
                        },
                    ));
                }
            }
        }

        SyncResult {
            completed: std::mem::take(&mut self.completed),
            failed: std::mem::take(&mut self.failed),
        }
    }

    pub fn config(&self) -> &CloudConfig {
        self.uploader.config()
    }
}

#[derive(Debug)]
pub struct SyncResult {
    pub completed: Vec<CloudPath>,
    pub failed: Vec<(PathBuf, CloudError)>,
}

impl SyncResult {
    pub fn is_success(&self) -> bool {
        self.failed.is_empty()
    }

    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    pub fn failed_count(&self) -> usize {
        self.failed.len()
    }
}

pub struct BatchUploader {
    uploader: Arc<dyn CloudUploader>,
    concurrency: usize,
}

impl BatchUploader {
    pub fn new(uploader: Arc<dyn CloudUploader>, concurrency: usize) -> Self {
        Self {
            uploader,
            concurrency: concurrency.max(1),
        }
    }

    pub async fn upload_all(&self, paths: Vec<PathBuf>) -> SyncResult {
        let (tx, mut rx) = mpsc::channel::<(PathBuf, Result<CloudPath>)>(self.concurrency * 2);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrency));

        let mut handles = Vec::new();
        let mut completed = Vec::new();
        let mut failed = Vec::new();

        for path in paths {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let uploader = self.uploader.clone();
            let tx = tx.clone();

            let handle = tokio::spawn(async move {
                let result = uploader.upload_file(&path).await;
                let _ = tx.send((path, result)).await;
                drop(permit);
            });
            handles.push(handle);
        }

        drop(tx);

        while let Some((path, result)) = rx.recv().await {
            match result {
                Ok(cloud_path) => completed.push(cloud_path),
                Err(e) => failed.push((path, e)),
            }
        }

        for handle in handles {
            let _ = handle.await;
        }

        SyncResult { completed, failed }
    }

    pub fn upload_all_blocking(&self, paths: Vec<PathBuf>) -> SyncResult {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        rt.block_on(self.upload_all(paths))
    }
}

pub fn sync_to_cloud_blocking(
    paths: Vec<PathBuf>,
    uploader: Arc<dyn CloudUploader>,
    concurrency: usize,
) -> SyncResult {
    let batch = BatchUploader::new(uploader, concurrency);
    batch.upload_all_blocking(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::cloud::CloudConfig;
    use object_store::memory::InMemory;
    use object_store::ObjectStore;
    use std::sync::Arc;

    struct TestUploader {
        store: Arc<InMemory>,
        config: CloudConfig,
    }

    impl TestUploader {
        fn new() -> Self {
            Self {
                store: Arc::new(InMemory::new()),
                config: CloudConfig::new("test-bucket"),
            }
        }
    }

    #[async_trait::async_trait]
    impl CloudUploader for TestUploader {
        async fn upload_file(&self, local_path: &std::path::Path) -> Result<CloudPath> {
            let contents = tokio::fs::read(local_path).await?;
            let key = local_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            let object_path = object_store::path::Path::from(key);
            self.store
                .put(&object_path, contents.into())
                .await
                .map_err(CloudError::from)?;

            Ok(CloudPath::new(&self.config.bucket, key))
        }

        async fn list_objects(&self, _prefix: Option<&str>) -> Result<Vec<CloudPath>> {
            Ok(Vec::new())
        }

        fn bucket(&self) -> &str {
            &self.config.bucket
        }

        fn endpoint(&self) -> Option<&str> {
            None
        }

        fn config(&self) -> &CloudConfig {
            &self.config
        }
    }

    #[tokio::test]
    async fn sync_manager_uploads_files() {
        let uploader = Arc::new(TestUploader::new());
        let mut manager = CloudSyncManager::new(uploader.clone());

        let temp_dir = tempfile::tempdir().unwrap();
        let file1 = temp_dir.path().join("file1.parquet");
        let file2 = temp_dir.path().join("file2.parquet");
        std::fs::write(&file1, b"data1").unwrap();
        std::fs::write(&file2, b"data2").unwrap();

        manager.spawn_upload(file1);
        manager.spawn_upload(file2);

        let result = manager.wait_for_all().await;

        assert!(result.is_success());
        assert_eq!(result.completed_count(), 2);
        assert_eq!(result.failed_count(), 0);
    }

    #[tokio::test]
    async fn batch_uploader_concurrent() {
        let uploader = Arc::new(TestUploader::new());
        let batch = BatchUploader::new(uploader, 4);

        let temp_dir = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for i in 0..10 {
            let path = temp_dir.path().join(format!("file{}.parquet", i));
            std::fs::write(&path, format!("data{}", i)).unwrap();
            paths.push(path);
        }

        let result = batch.upload_all(paths).await;

        assert!(result.is_success());
        assert_eq!(result.completed_count(), 10);
    }

    #[test]
    fn batch_uploader_blocking() {
        let uploader = Arc::new(TestUploader::new());
        let batch = BatchUploader::new(uploader, 2);

        let temp_dir = tempfile::tempdir().unwrap();
        let file = temp_dir.path().join("test.parquet");
        std::fs::write(&file, b"test data").unwrap();

        let result = batch.upload_all_blocking(vec![file]);

        assert!(result.is_success());
        assert_eq!(result.completed_count(), 1);
    }

    #[test]
    fn sync_result_status() {
        let result = SyncResult {
            completed: vec![CloudPath::new("bucket", "key")],
            failed: vec![],
        };
        assert!(result.is_success());

        let result_with_failure = SyncResult {
            completed: vec![],
            failed: vec![(PathBuf::from("/tmp/test"), CloudError::NoCredentials)],
        };
        assert!(!result_with_failure.is_success());
    }
}
