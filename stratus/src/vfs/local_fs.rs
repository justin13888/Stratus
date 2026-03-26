use crate::errors::VfsError;
use futures::stream::{Stream, StreamExt};
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncSeek};
use tokio_stream::wrappers::ReadDirStream;
use tracing::debug;

use super::{Vfs, VfsEntry, VfsFile, VfsMetadata};

/// Map an `io::Error` to the appropriate `VfsError` variant for the given path.
fn map_io_err(e: io::Error, path: &Path) -> VfsError {
    match e.kind() {
        io::ErrorKind::NotFound => VfsError::NotFound(path.to_path_buf()),
        io::ErrorKind::PermissionDenied => VfsError::PermissionDenied(path.to_path_buf()),
        _ => VfsError::IoError(e),
    }
}

/// A VFS file handle backed by the local filesystem
pub struct LocalFile {
    file: fs::File,
}

impl LocalFile {
    pub fn new(file: fs::File) -> Self {
        Self { file }
    }
}

impl VfsFile for LocalFile {
    async fn size(&self) -> Result<u64, VfsError> {
        let metadata = self.file.metadata().await?;
        Ok(metadata.len())
    }
}

impl AsyncRead for LocalFile {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.file).poll_read(cx, buf)
    }
}

impl AsyncSeek for LocalFile {
    fn start_seek(mut self: std::pin::Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        std::pin::Pin::new(&mut self.file).start_seek(position)
    }

    fn poll_complete(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<u64>> {
        std::pin::Pin::new(&mut self.file).poll_complete(cx)
    }
}

/// Local filesystem VFS backend
///
/// This backend uses tokio::fs to interact with the local filesystem.
/// It's designed to be a drop-in replacement for direct fs operations
/// while conforming to the VFS trait.
#[derive(Clone)]
pub struct LocalFs;

impl LocalFs {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LocalFs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs for LocalFs {
    type File = LocalFile;

    async fn canonicalize(&self, path: &Path) -> Result<PathBuf, VfsError> {
        fs::canonicalize(path).await.map_err(|e| map_io_err(e, path))
    }

    async fn metadata(&self, path: &Path) -> Result<VfsMetadata, VfsError> {
        // Use symlink_metadata to NOT follow symlinks
        // This is crucial for security - we need to detect symlinks before following them
        let metadata = fs::symlink_metadata(path)
            .await
            .map_err(|e| map_io_err(e, path))?;
        Ok(VfsMetadata {
            is_dir: metadata.is_dir(),
            is_file: metadata.is_file(),
            is_symlink: metadata.is_symlink(),
            len: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }

    fn read_dir(
        &self,
        path: &Path,
    ) -> Pin<Box<dyn Stream<Item = Result<VfsEntry, VfsError>> + Send + '_>> {
        let path = path.to_path_buf();
        Box::pin(async_stream::stream! {
            match fs::read_dir(&path).await {
                Ok(read_dir) => {
                    let mut stream = ReadDirStream::new(read_dir);
                    while let Some(entry_result) = stream.next().await {
                        match entry_result {
                            Ok(entry) => {
                                let name = entry.file_name().to_string_lossy().to_string();
                                // Use symlink_metadata to NOT follow symlinks
                                // This ensures we can detect symlinks before following them
                                match fs::symlink_metadata(entry.path()).await {
                                    Ok(metadata) => {
                                        yield Ok(VfsEntry {
                                            name,
                                            metadata: VfsMetadata {
                                                is_dir: metadata.is_dir(),
                                                is_file: metadata.is_file(),
                                                is_symlink: metadata.is_symlink(),
                                                len: metadata.len(),
                                                modified: metadata.modified().ok(),
                                            },
                                        });
                                    }
                                    Err(e) => {
                                        debug!(
                                            "Failed to get metadata for entry '{}' in {:?}: {}",
                                            name, path, e
                                        );
                                        yield Err(VfsError::IoError(e));
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("Failed to read directory entry in {:?}: {}", path, e);
                                yield Err(VfsError::IoError(e));
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to open directory {:?}: {}", path, e);
                    yield Err(VfsError::IoError(e));
                }
            }
        })
    }

    async fn open(&self, path: &Path) -> Result<Self::File, VfsError> {
        let file = fs::File::open(path)
            .await
            .map_err(|e| map_io_err(e, path))?;
        Ok(LocalFile::new(file))
    }

    async fn create_dir_all(&self, path: &Path) -> Result<(), VfsError> {
        fs::create_dir_all(path)
            .await
            .map_err(|e| map_io_err(e, path))
    }

    async fn write(&self, path: &Path, contents: &[u8]) -> Result<(), VfsError> {
        fs::write(path, contents)
            .await
            .map_err(|e| map_io_err(e, path))
    }

    async fn read_to_string(&self, path: &Path) -> Result<String, VfsError> {
        fs::read_to_string(path)
            .await
            .map_err(|e| map_io_err(e, path))
    }

    async fn remove_file(&self, path: &Path) -> Result<(), VfsError> {
        fs::remove_file(path)
            .await
            .map_err(|e| map_io_err(e, path))
    }

    async fn remove_dir_all(&self, path: &Path) -> Result<(), VfsError> {
        fs::remove_dir_all(path)
            .await
            .map_err(|e| map_io_err(e, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as std_fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_symlink_detection() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create a file inside the share
        let inside_file = base_path.join("inside.txt");
        std_fs::write(&inside_file, "inside content").unwrap();

        // Create a directory outside the share
        let outside_dir = TempDir::new().unwrap();
        let outside_file = outside_dir.path().join("outside.txt");
        std_fs::write(&outside_file, "outside content").unwrap();

        // Create a symlink inside the share pointing to the outside file
        let symlink_path = base_path.join("evil_link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_file, &symlink_path).unwrap();

        let vfs = LocalFs::new();

        // Test that we can detect the symlink
        let metadata = vfs.metadata(&symlink_path).await.unwrap();
        assert!(metadata.is_symlink, "Should detect symlink");

        // Test that validate_path_within_base rejects the symlink
        let canonical_base = vfs.canonicalize(base_path).await.unwrap();
        let is_valid = vfs
            .validate_path_within_base(&symlink_path, &canonical_base)
            .await
            .unwrap();
        assert!(!is_valid, "Symlink pointing outside should be rejected");

        // Test that a regular file inside passes validation
        let is_valid = vfs
            .validate_path_within_base(&inside_file, &canonical_base)
            .await
            .unwrap();
        assert!(is_valid, "Regular file inside should be accepted");

        // Create a symlink inside pointing to another file inside
        let inside_link = base_path.join("inside_link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&inside_file, &inside_link).unwrap();

        let is_valid = vfs
            .validate_path_within_base(&inside_link, &canonical_base)
            .await
            .unwrap();
        assert!(is_valid, "Symlink pointing inside should be accepted");
    }

    #[tokio::test]
    async fn test_path_traversal_prevention() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create subdirectory
        let subdir = base_path.join("subdir");
        std_fs::create_dir(&subdir).unwrap();

        // Create a file in the base directory
        let base_file = base_path.join("secret.txt");
        std_fs::write(&base_file, "secret").unwrap();

        let vfs = LocalFs::new();
        let canonical_subdir = vfs.canonicalize(&subdir).await.unwrap();

        // Try to access parent directory using ..
        let traversal_path = subdir.join("../secret.txt");

        let is_valid = vfs
            .validate_path_within_base(&traversal_path, &canonical_subdir)
            .await
            .unwrap();
        assert!(!is_valid, "Path traversal using .. should be rejected");
    }
}
