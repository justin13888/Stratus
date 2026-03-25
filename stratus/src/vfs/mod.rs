pub mod backend;
pub mod local_fs;

use crate::errors::VfsError;
use futures::stream::Stream;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncSeek};

/// Represents metadata about a file or directory in the VFS
#[derive(Debug, Clone)]
pub struct VfsMetadata {
    pub is_dir: bool,
    #[allow(dead_code)]
    pub is_file: bool,
    pub is_symlink: bool,
    pub len: u64,
    pub modified: Option<SystemTime>,
}

/// Represents a single entry in a directory listing
#[derive(Debug, Clone)]
pub struct VfsEntry {
    pub name: String,
    pub metadata: VfsMetadata,
}

/// A file handle that can be read and seeked
pub trait VfsFile: AsyncRead + AsyncSeek + Unpin + Send {
    /// Get the size of the file
    #[allow(dead_code)]
    fn size(&self) -> impl Future<Output = Result<u64, VfsError>> + Send;
}

/// Virtual File System trait that abstracts filesystem operations
///
/// This trait provides a uniform interface for interacting with different
/// storage backends (local filesystem, S3, etc.). All implementations must
/// provide thread-safe, async operations.
pub trait Vfs: Send + Sync + Clone + 'static {
    type File: VfsFile;

    /// Canonicalize a path to resolve any symlinks or relative components
    ///
    /// Returns an absolute path with all symlinks resolved. This is used
    /// for security checks to ensure paths don't escape their boundaries.
    fn canonicalize(&self, path: &Path) -> impl Future<Output = Result<PathBuf, VfsError>> + Send;

    /// Get metadata for a file or directory
    ///
    /// Returns metadata including type (file/dir/symlink), size, and modification time.
    /// This should use symlink_metadata to NOT follow symlinks, allowing detection
    /// of symlinks before they are resolved.
    fn metadata(&self, path: &Path) -> impl Future<Output = Result<VfsMetadata, VfsError>> + Send;

    /// Validate that a path (which may be a symlink) resolves to a location within the allowed base path
    ///
    /// This is a critical security function that prevents symlink attacks. It:
    /// 1. Checks if the path is a symlink using metadata()
    /// 2. If it is a symlink, canonicalizes it to get the real target
    /// 3. Verifies the canonical target is within the allowed base path
    ///
    /// Returns Ok(true) if the path is safe to access, Ok(false) if it's a symlink pointing
    /// outside the base path, or Err if there was an error checking.
    fn validate_path_within_base(
        &self,
        path: &Path,
        base: &Path,
    ) -> impl Future<Output = Result<bool, VfsError>> + Send {
        async move {
            // First, get metadata without following symlinks
            let metadata = self.metadata(path).await?;

            // If it's a symlink, we need to check where it points
            if metadata.is_symlink {
                // Canonicalize to resolve the symlink target
                match self.canonicalize(path).await {
                    Ok(canonical_target) => {
                        // Check if the resolved target is within the base path
                        Ok(self.path_starts_with(&canonical_target, base))
                    }
                    Err(_) => {
                        // If canonicalization fails (broken symlink), deny access
                        Ok(false)
                    }
                }
            } else {
                // Not a symlink, perform normal path check
                // We still need to canonicalize to handle .. and . in the path
                match self.canonicalize(path).await {
                    Ok(canonical_path) => Ok(self.path_starts_with(&canonical_path, base)),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    /// Check if a path exists
    #[allow(dead_code)]
    fn exists(&self, path: &Path) -> impl Future<Output = bool> + Send {
        async move { self.metadata(path).await.is_ok() }
    }

    /// Read directory entries as a stream
    ///
    /// Returns a stream of directory entries. This allows for efficient
    /// processing of large directories without loading all entries into memory.
    /// Implementations can stream entries as they are read from the backend.
    fn read_dir(
        &self,
        path: &Path,
    ) -> Pin<Box<dyn Stream<Item = Result<VfsEntry, VfsError>> + Send + '_>>;

    /// Open a file for reading
    ///
    /// Returns a file handle that can be used for streaming reads and seeking.
    fn open(&self, path: &Path) -> impl Future<Output = Result<Self::File, VfsError>> + Send;

    /// Create all parent directories for a path if they don't exist
    ///
    /// Similar to `mkdir -p` on Unix systems.
    fn create_dir_all(&self, path: &Path) -> impl Future<Output = Result<(), VfsError>> + Send;

    /// Write data to a file, creating it if it doesn't exist
    ///
    /// This is primarily used for caching operations.
    fn write(
        &self,
        path: &Path,
        contents: &[u8],
    ) -> impl Future<Output = Result<(), VfsError>> + Send;

    /// Read the entire contents of a file as a string
    ///
    /// Used for reading cached HTML files.
    fn read_to_string(&self, path: &Path) -> impl Future<Output = Result<String, VfsError>> + Send;

    /// Check if a path starts with another path (for security checks)
    ///
    /// This is used to ensure that canonicalized paths don't escape
    /// their intended boundaries (e.g., share directories).
    fn path_starts_with(&self, path: &Path, base: &Path) -> bool {
        path.starts_with(base)
    }

    /// Join a base path with a relative path
    ///
    /// Helper method for constructing paths within the VFS.
    fn join(&self, base: &Path, relative: &str) -> PathBuf {
        base.join(relative)
    }

    /// Get the file name component of a path
    fn file_name(&self, path: &Path) -> Option<String> {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
    }
}
