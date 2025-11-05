use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use eyre::Result;
use std::path::PathBuf;
use tokio::fs;
use tracing::warn;

use super::html::generate_directory_html;
use crate::config::ShareConfig;

#[derive(Debug)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<std::time::SystemTime>,
}

pub async fn serve_directory_listing(
    share_name: &str,
    relative_path: &str,
    dir_path: &PathBuf,
    share_config: &ShareConfig,
    cache_dir: &PathBuf,
) -> Response {
    // Create cache directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(cache_dir).await {
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
        fs::metadata(&cache_file).await,
        fs::metadata(dir_path).await,
    ) && let (Ok(cache_mtime), Ok(dir_mtime)) =
        (cache_metadata.modified(), dir_metadata.modified())
        && cache_mtime > dir_mtime // Cache is valid if newer than directory
        && let Ok(cached_html) = fs::read_to_string(&cache_file).await
    {
        return Html(cached_html).into_response();
    }

    // Generate fresh listing
    let entries = match read_directory_entries(dir_path, share_config).await {
        Ok(e) => e,
        Err(e) => {
            warn!("Failed to read directory {:?}: {}", dir_path, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read directory",
            )
                .into_response();
        }
    };

    let html = generate_directory_html(share_name, relative_path, entries);

    // Cache asynchronously in background
    let cache_file_clone = cache_file.clone();
    let html_clone = html.clone();
    tokio::spawn(async move {
        if let Err(e) = fs::write(&cache_file_clone, &html_clone).await {
            warn!("Failed to cache directory listing: {}", e);
        }
    });

    Html(html).into_response()
}

async fn read_directory_entries(
    dir_path: &PathBuf,
    share_config: &ShareConfig,
) -> Result<Vec<DirEntry>> {
    let mut entries = Vec::with_capacity(256); // Pre-allocate for better performance
    let mut read_dir = fs::read_dir(dir_path).await?;

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

    while let Some(entry) = read_dir.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();

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

        let metadata = entry.metadata().await?;
        let is_dir = metadata.is_dir();

        // Skip symlinks if not configured to follow them
        if metadata.is_symlink() && !share_config.follow_symlinks {
            continue;
        }

        entries.push(DirEntry {
            name,
            is_dir,
            size: metadata.len(),
            modified: metadata.modified().ok(),
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
