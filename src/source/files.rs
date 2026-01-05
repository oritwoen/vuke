//! Files source - generate keys from file contents.

use anyhow::Result;
use indicatif::ProgressBar;
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use super::{ProcessStats, Source};
use crate::derive::KeyDeriver;
use crate::matcher::Matcher;
use crate::output::Output;
use crate::transform::{Input, Transform};

pub struct FilesSource {
    files: Vec<PathBuf>,
}

impl FilesSource {
    pub fn from_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            anyhow::bail!("File not found: {}", path.display());
        }
        if !path.is_file() {
            anyhow::bail!("Not a file: {}", path.display());
        }
        Ok(Self {
            files: vec![path.to_path_buf()],
        })
    }

    pub fn from_dir(path: &Path) -> Result<Self> {
        if !path.exists() {
            anyhow::bail!("Directory not found: {}", path.display());
        }
        if !path.is_dir() {
            anyhow::bail!("Not a directory: {}", path.display());
        }

        let files = collect_files_recursive(path)?;

        if files.is_empty() {
            anyhow::bail!("No files found in directory: {}", path.display());
        }

        Ok(Self { files })
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

fn collect_files_recursive(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files_inner(dir, &mut files)?;
    Ok(files)
}

fn collect_files_inner(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        // Skip symlinks to avoid loops and security issues
        if file_type.is_symlink() {
            continue;
        }

        if file_type.is_file() {
            files.push(path);
        } else if file_type.is_dir() {
            collect_files_inner(&path, files)?;
        }
    }

    Ok(())
}

fn read_file_contents(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

impl Source for FilesSource {
    fn process(
        &self,
        transforms: &[Box<dyn Transform>],
        matcher: Option<&Matcher>,
        output: &dyn Output,
    ) -> Result<ProcessStats> {
        let pb = ProgressBar::new(self.files.len() as u64);
        pb.set_style(crate::default_progress_style());

        let deriver = KeyDeriver::new();
        let stats = std::sync::atomic::AtomicU64::new(0);
        let matches = std::sync::atomic::AtomicU64::new(0);

        self.files.par_iter().for_each(|path| {
            let contents = match read_file_contents(path) {
                Ok(c) => c,
                Err(_) => {
                    pb.inc(1);
                    return;
                }
            };

            let label = path.display().to_string();
            let input = Input::from_blob(contents, label);
            let inputs = [input];
            let mut buffer = Vec::with_capacity(transforms.len() * 2);

            for transform in transforms {
                buffer.clear();
                transform.apply_batch(&inputs, &mut buffer);

                for (source, key) in &buffer {
                    let derived = deriver.derive(key);

                    if let Some(m) = matcher {
                        if let Some(match_info) = m.check(&derived) {
                            output
                                .hit(source, transform.name(), &derived, &match_info)
                                .ok();
                            matches.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    } else {
                        output.key(source, transform.name(), &derived).ok();
                    }

                    stats.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }

            pb.inc(1);
        });

        pb.finish_and_clear();

        Ok(ProcessStats {
            inputs_processed: self.files.len() as u64,
            keys_generated: stats.load(std::sync::atomic::Ordering::Relaxed),
            matches_found: matches.load(std::sync::atomic::Ordering::Relaxed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{tempdir, NamedTempFile};

    #[test]
    fn test_from_file_single() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"test content").unwrap();

        let source = FilesSource::from_file(file.path()).unwrap();
        assert_eq!(source.file_count(), 1);
    }

    #[test]
    fn test_from_file_not_found() {
        let result = FilesSource::from_file(Path::new("/nonexistent/path/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_from_dir_recursive() {
        let dir = tempdir().unwrap();
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        fs::write(dir.path().join("file1.txt"), b"content1").unwrap();
        fs::write(subdir.join("file2.txt"), b"content2").unwrap();

        let source = FilesSource::from_dir(dir.path()).unwrap();
        assert_eq!(source.file_count(), 2);
    }

    #[test]
    fn test_from_dir_empty() {
        let dir = tempdir().unwrap();
        let result = FilesSource::from_dir(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_collect_files_skips_symlinks() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("file.txt"), b"content").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(dir.path().join("file.txt"), dir.path().join("link.txt")).unwrap();
        }

        let source = FilesSource::from_dir(dir.path()).unwrap();
        assert_eq!(source.file_count(), 1);
    }
}
