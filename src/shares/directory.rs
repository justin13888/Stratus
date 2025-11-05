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

    // Check if we have a cached version
    // For now, we'll regenerate each time for simplicity
    // TODO: Implement proper cache invalidation based on directory mtime

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

    // Cache the HTML
    if let Err(e) = fs::write(&cache_file, &html).await {
        warn!("Failed to cache directory listing: {}", e);
    }

    Html(html).into_response()
}

async fn read_directory_entries(
    dir_path: &PathBuf,
    share_config: &ShareConfig,
) -> Result<Vec<DirEntry>> {
    let mut entries = Vec::new();
    let mut read_dir = fs::read_dir(dir_path).await?;

    while let Some(entry) = read_dir.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip hidden files if configured
        if share_config.hide_dot_files && name.starts_with('.') {
            continue;
        }

        // Check exclude patterns
        if !share_config.exclude_patterns.is_empty() {
            let should_exclude = share_config.exclude_patterns.iter().any(|pattern| {
                glob::Pattern::new(pattern)
                    .map(|p| p.matches(&name))
                    .unwrap_or(false)
            });
            if should_exclude {
                continue;
            }
        }

        // Check include patterns (if specified)
        if !share_config.include_patterns.is_empty() {
            let should_include = share_config.include_patterns.iter().any(|pattern| {
                glob::Pattern::new(pattern)
                    .map(|p| p.matches(&name))
                    .unwrap_or(false)
            });
            if !should_include {
                continue;
            }
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

    // Sort: directories first, then by name
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    Ok(entries)
}
