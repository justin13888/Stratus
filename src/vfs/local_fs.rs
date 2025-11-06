use futures::stream::{Stream, StreamExt};
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncSeek};
use tokio_stream::wrappers::ReadDirStream;

use super::{Vfs, VfsEntry, VfsFile, VfsMetadata};

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
    async fn size(&self) -> io::Result<u64> {
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

    async fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        fs::canonicalize(path).await
    }

    async fn metadata(&self, path: &Path) -> io::Result<VfsMetadata> {
        let metadata = fs::metadata(path).await?;
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
    ) -> Pin<Box<dyn Stream<Item = io::Result<VfsEntry>> + Send + '_>> {
        let path = path.to_path_buf();
        Box::pin(async_stream::stream! {
            match fs::read_dir(&path).await {
                Ok(read_dir) => {
                    let mut stream = ReadDirStream::new(read_dir);
                    while let Some(entry_result) = stream.next().await {
                        match entry_result {
                            Ok(entry) => {
                                let name = entry.file_name().to_string_lossy().to_string();
                                match entry.metadata().await {
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
                                        yield Err(e);
                                    }
                                }
                            }
                            Err(e) => {
                                yield Err(e);
                            }
                        }
                    }
                }
                Err(e) => {
                    yield Err(e);
                }
            }
        })
    }

    async fn open(&self, path: &Path) -> io::Result<Self::File> {
        let file = fs::File::open(path).await?;
        Ok(LocalFile::new(file))
    }

    async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(path).await
    }

    async fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        fs::write(path, contents).await
    }

    async fn read_to_string(&self, path: &Path) -> io::Result<String> {
        fs::read_to_string(path).await
    }
}
