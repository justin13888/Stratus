use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use futures::StreamExt;
use std::path::Path;
use tracing::{debug, warn};

use super::html::generate_directory_html;
use crate::config::ShareConfig;
use crate::errors::ShareError;
use crate::vfs::Vfs;

#[derive(Debug)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<std::time::SystemTime>,
}

pub async fn serve_directory_listing<V: Vfs>(
    share_name: &str,
    relative_path: &str,
    dir_path: &Path,
    share_config: &ShareConfig,
    cache_dir: &Path,
    canonical_share_path: &Path,
    vfs: &V,
) -> Response {
    use std::time::Instant;
    let start = Instant::now();

    // Create cache directory if it doesn't exist
    if let Err(e) = vfs.create_dir_all(cache_dir).await {
        warn!("Failed to create cache directory: {}", e);
    }

    // Generate cache key from path
    let cache_key = format!("{}/{}", share_name, relative_path);
    let cache_file = cache_dir.join(format!(
        "{}.html",
        cache_key.replace('/', "_").replace("..", "_")
    ));

    // Check cache with mtime validation
    if let (Ok(cache_metadata), Ok(dir_metadata)) = (
        vfs.metadata(&cache_file).await,
        vfs.metadata(dir_path).await,
    ) && let (Some(cache_mtime), Some(dir_mtime)) =
        (cache_metadata.modified, dir_metadata.modified)
        && cache_mtime > dir_mtime // Cache is valid if newer than directory
        && let Ok(cached_html) = vfs.read_to_string(&cache_file).await
    {
        return Html(cached_html).into_response();
    }

    // Generate fresh listing
    let entries =
        match read_directory_entries(dir_path, share_config, canonical_share_path, vfs).await {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to read directory {:?}: {}", dir_path, e);
                crate::metrics::record_file_operation("read_directory", start.elapsed());
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read directory",
                )
                    .into_response();
            }
        };

    crate::metrics::record_file_operation("read_directory", start.elapsed());

    let html = generate_directory_html(share_name, relative_path, entries);

    // Cache asynchronously in background
    let cache_file_clone = cache_file.clone();
    let html_clone = html.clone();
    let vfs_clone = vfs.clone();
    tokio::spawn(async move {
        if let Err(e) = vfs_clone
            .write(&cache_file_clone, html_clone.as_bytes())
            .await
        {
            warn!("Failed to cache directory listing: {}", e);
        }
    });

    Html(html).into_response()
}

async fn read_directory_entries<V: Vfs>(
    dir_path: &Path,
    share_config: &ShareConfig,
    canonical_share_path: &Path,
    vfs: &V,
) -> Result<Vec<DirEntry>, ShareError> {
    let mut entries = Vec::with_capacity(256); // Pre-allocate for better performance
    let mut vfs_entries = vfs.read_dir(dir_path);

    // Compile glob patterns once (outside the loop)
    let exclude_patterns: Vec<_> = share_config
        .exclude_patterns
        .iter()
        .filter_map(|pattern| glob::Pattern::new(pattern).ok())
        .collect();

    let include_patterns: Vec<_> = share_config
        .include_patterns
        .iter()
        .filter_map(|pattern| glob::Pattern::new(pattern).ok())
        .collect();

    // Process entries from the stream
    while let Some(entry_result) = vfs_entries.next().await {
        let entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                // Log individual entry errors but continue processing others
                debug!("Error reading directory entry in {:?}: {}", dir_path, e);
                return Err(ShareError::DirectoryReadError(format!(
                    "Failed to read directory entry: {e}",
                )));
            }
        };
        let name = entry.name;

        // Skip hidden files if configured
        if share_config.hide_dot_files && name.starts_with('.') {
            continue;
        }

        // Check exclude patterns
        if !exclude_patterns.is_empty() && exclude_patterns.iter().any(|p| p.matches(&name)) {
            continue;
        }

        // Check include patterns (if specified)
        if !include_patterns.is_empty() && !include_patterns.iter().any(|p| p.matches(&name)) {
            continue;
        }

        let is_dir = entry.metadata.is_dir;

        // Skip symlinks if not configured to follow them
        if entry.metadata.is_symlink && !share_config.follow_symlinks {
            continue;
        }

        // Security check: if this is a symlink and follow_symlinks is enabled,
        // verify the symlink target stays within the share boundary
        if entry.metadata.is_symlink && share_config.follow_symlinks {
            let entry_path = dir_path.join(&name);
            match vfs
                .validate_path_within_base(&entry_path, canonical_share_path)
                .await
            {
                Ok(true) => {
                    // Symlink target is within bounds, allow it
                }
                Ok(false) => {
                    // Symlink points outside the share, skip it
                    warn!(
                        "Skipping symlink that points outside share: {:?}",
                        entry_path
                    );
                    continue;
                }
                Err(e) => {
                    // Error validating symlink, skip it to be safe
                    warn!("Error validating symlink {:?}: {}, skipping", entry_path, e);
                    continue;
                }
            }
        }

        entries.push(DirEntry {
            name,
            is_dir,
            size: entry.metadata.len,
            modified: entry.metadata.modified,
        });
    }

    // Sort: directories first, then by name (using unstable_sort for better performance)
    entries.sort_unstable_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use crate::test_utils::ShareConfigBuilder;
    use crate::vfs::backend::LocalFs;

    async fn body_text(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_serve_directory_basic() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("alpha.txt"), "a").unwrap();
        std::fs::write(dir.path().join("beta.txt"), "b").unwrap();
        let cfg = ShareConfigBuilder::new(dir.path()).build();
        let vfs = LocalFs::new();
        let resp = serve_directory_listing(
            "share", "", dir.path(), &cfg, cache_dir.path(), dir.path(), &vfs,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_text(resp).await;
        assert!(body.contains("alpha.txt"), "expected alpha.txt in listing");
        assert!(body.contains("beta.txt"), "expected beta.txt in listing");
    }

    #[tokio::test]
    async fn test_serve_directory_hide_dot_files() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".hidden"), "secret").unwrap();
        std::fs::write(dir.path().join("visible.txt"), "public").unwrap();
        let cfg = ShareConfigBuilder::new(dir.path()).hide_dot_files(true).build();
        let vfs = LocalFs::new();
        let resp = serve_directory_listing(
            "share", "", dir.path(), &cfg, cache_dir.path(), dir.path(), &vfs,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_text(resp).await;
        assert!(!body.contains(".hidden"), ".hidden should be absent");
        assert!(body.contains("visible.txt"), "visible.txt should appear");
    }

    #[tokio::test]
    async fn test_serve_directory_exclude_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("keep.txt"), "a").unwrap();
        std::fs::write(dir.path().join("remove.tmp"), "b").unwrap();
        let cfg = ShareConfigBuilder::new(dir.path())
            .with_exclude_patterns(vec!["*.tmp"])
            .build();
        let vfs = LocalFs::new();
        let resp = serve_directory_listing(
            "share", "", dir.path(), &cfg, cache_dir.path(), dir.path(), &vfs,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_text(resp).await;
        assert!(body.contains("keep.txt"), "keep.txt should appear");
        assert!(!body.contains("remove.tmp"), "remove.tmp should be excluded");
    }

    #[tokio::test]
    async fn test_serve_directory_sort_dirs_before_files() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("zzz_file.txt"), "f").unwrap();
        std::fs::create_dir(dir.path().join("aaa_subdir")).unwrap();
        let cfg = ShareConfigBuilder::new(dir.path()).build();
        let vfs = LocalFs::new();
        let resp = serve_directory_listing(
            "share", "", dir.path(), &cfg, cache_dir.path(), dir.path(), &vfs,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_text(resp).await;
        let dir_pos = body.find("aaa_subdir").unwrap_or(usize::MAX);
        let file_pos = body.find("zzz_file.txt").unwrap_or(usize::MAX);
        assert!(
            dir_pos < file_pos,
            "directory should appear before file in listing"
        );
    }
}
