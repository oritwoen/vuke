use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::error::CloudError;

pub trait UploadProgress: Send + Sync {
    fn on_upload_start(&self, path: &Path, size: u64);
    fn on_upload_complete(&self, path: &Path, duration: Duration);
    fn on_upload_error(&self, path: &Path, error: &CloudError);
    fn on_retry(&self, path: &Path, attempt: u32, max_attempts: u32);
}

pub struct NoOpProgress;

impl UploadProgress for NoOpProgress {
    fn on_upload_start(&self, _path: &Path, _size: u64) {}
    fn on_upload_complete(&self, _path: &Path, _duration: Duration) {}
    fn on_upload_error(&self, _path: &Path, _error: &CloudError) {}
    fn on_retry(&self, _path: &Path, _attempt: u32, _max_attempts: u32) {}
}

pub struct UploadStats {
    pub uploads_started: AtomicU64,
    pub uploads_completed: AtomicU64,
    pub uploads_failed: AtomicU64,
    pub bytes_uploaded: AtomicU64,
    pub total_retries: AtomicU64,
}

impl Default for UploadStats {
    fn default() -> Self {
        Self::new()
    }
}

impl UploadStats {
    pub fn new() -> Self {
        Self {
            uploads_started: AtomicU64::new(0),
            uploads_completed: AtomicU64::new(0),
            uploads_failed: AtomicU64::new(0),
            bytes_uploaded: AtomicU64::new(0),
            total_retries: AtomicU64::new(0),
        }
    }

    pub fn started(&self) -> u64 {
        self.uploads_started.load(Ordering::Relaxed)
    }

    pub fn completed(&self) -> u64 {
        self.uploads_completed.load(Ordering::Relaxed)
    }

    pub fn failed(&self) -> u64 {
        self.uploads_failed.load(Ordering::Relaxed)
    }

    pub fn bytes(&self) -> u64 {
        self.bytes_uploaded.load(Ordering::Relaxed)
    }

    pub fn retries(&self) -> u64 {
        self.total_retries.load(Ordering::Relaxed)
    }

    pub fn pending(&self) -> u64 {
        self.started()
            .saturating_sub(self.completed() + self.failed())
    }
}

pub struct StatsProgress {
    stats: Arc<UploadStats>,
}

impl StatsProgress {
    pub fn new(stats: Arc<UploadStats>) -> Self {
        Self { stats }
    }

    pub fn stats(&self) -> &Arc<UploadStats> {
        &self.stats
    }
}

impl UploadProgress for StatsProgress {
    fn on_upload_start(&self, _path: &Path, size: u64) {
        self.stats.uploads_started.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_uploaded.fetch_add(size, Ordering::Relaxed);
    }

    fn on_upload_complete(&self, _path: &Path, _duration: Duration) {
        self.stats.uploads_completed.fetch_add(1, Ordering::Relaxed);
    }

    fn on_upload_error(&self, _path: &Path, _error: &CloudError) {
        self.stats.uploads_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn on_retry(&self, _path: &Path, _attempt: u32, _max_attempts: u32) {
        self.stats.total_retries.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn noop_progress_does_nothing() {
        let progress = NoOpProgress;
        let path = PathBuf::from("/tmp/test.parquet");

        progress.on_upload_start(&path, 1000);
        progress.on_upload_complete(&path, Duration::from_secs(1));
        progress.on_upload_error(&path, &CloudError::NoCredentials);
        progress.on_retry(&path, 1, 5);
    }

    #[test]
    fn stats_progress_tracks_uploads() {
        let stats = Arc::new(UploadStats::new());
        let progress = StatsProgress::new(stats.clone());
        let path = PathBuf::from("/tmp/test.parquet");

        assert_eq!(stats.started(), 0);
        assert_eq!(stats.completed(), 0);

        progress.on_upload_start(&path, 1000);
        assert_eq!(stats.started(), 1);
        assert_eq!(stats.bytes(), 1000);
        assert_eq!(stats.pending(), 1);

        progress.on_upload_complete(&path, Duration::from_secs(1));
        assert_eq!(stats.completed(), 1);
        assert_eq!(stats.pending(), 0);
    }

    #[test]
    fn stats_progress_tracks_failures() {
        let stats = Arc::new(UploadStats::new());
        let progress = StatsProgress::new(stats.clone());
        let path = PathBuf::from("/tmp/test.parquet");

        progress.on_upload_start(&path, 500);
        progress.on_retry(&path, 1, 5);
        progress.on_retry(&path, 2, 5);
        progress.on_upload_error(&path, &CloudError::NoCredentials);

        assert_eq!(stats.failed(), 1);
        assert_eq!(stats.retries(), 2);
        assert_eq!(stats.pending(), 0);
    }

    #[test]
    fn upload_stats_default() {
        let stats = UploadStats::default();
        assert_eq!(stats.started(), 0);
        assert_eq!(stats.completed(), 0);
        assert_eq!(stats.failed(), 0);
        assert_eq!(stats.bytes(), 0);
    }
}
