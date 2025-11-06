pub mod backend;
pub mod local_fs;

use futures::stream::Stream;
use std::io;
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
    fn size(&self) -> impl std::future::Future<Output = io::Result<u64>> + Send;
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
    fn canonicalize(
        &self,
        path: &Path,
    ) -> impl std::future::Future<Output = io::Result<PathBuf>> + Send;

    /// Get metadata for a file or directory
    ///
    /// Returns metadata including type (file/dir/symlink), size, and modification time.
    fn metadata(
        &self,
        path: &Path,
    ) -> impl std::future::Future<Output = io::Result<VfsMetadata>> + Send;

    /// Check if a path exists
    fn exists(&self, path: &Path) -> impl std::future::Future<Output = bool> + Send {
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
    ) -> Pin<Box<dyn Stream<Item = io::Result<VfsEntry>> + Send + '_>>;

    /// Open a file for reading
    ///
    /// Returns a file handle that can be used for streaming reads and seeking.
    fn open(&self, path: &Path)
    -> impl std::future::Future<Output = io::Result<Self::File>> + Send;

    /// Create all parent directories for a path if they don't exist
    ///
    /// Similar to `mkdir -p` on Unix systems.
    fn create_dir_all(
        &self,
        path: &Path,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send;

    /// Write data to a file, creating it if it doesn't exist
    ///
    /// This is primarily used for caching operations.
    fn write(
        &self,
        path: &Path,
        contents: &[u8],
    ) -> impl std::future::Future<Output = io::Result<()>> + Send;

    /// Read the entire contents of a file as a string
    ///
    /// Used for reading cached HTML files.
    fn read_to_string(
        &self,
        path: &Path,
    ) -> impl std::future::Future<Output = io::Result<String>> + Send;

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
