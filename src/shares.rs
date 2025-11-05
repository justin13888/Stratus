use axum::{
    extract::{Path, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use eyre::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tracing::{debug, warn};

use crate::config::ShareConfig;

#[derive(Clone)]
pub struct ShareState {
    pub shares: Arc<HashMap<String, ShareConfig>>,
    pub cache_dir: PathBuf,
}

impl ShareState {
    pub fn new(shares: HashMap<String, ShareConfig>, cache_dir: PathBuf) -> Self {
        Self {
            shares: Arc::new(shares),
            cache_dir,
        }
    }
}

/// Handle requests to /shares/{share_name}/**
pub async fn serve_share(
    State(state): State<ShareState>,
    Path(path_parts): Path<String>,
) -> Response {
    // Split path into share name and file path
    let parts: Vec<&str> = path_parts.splitn(2, '/').collect();
    let share_name = parts[0];
    let file_path = if parts.len() > 1 { parts[1] } else { "" };

    debug!("Serving share '{}' path '{}'", share_name, file_path);

    // Find the share config
    let share_config = match state.shares.get(share_name) {
        Some(config) => config,
        None => {
            warn!("Share '{}' not found", share_name);
            return (StatusCode::NOT_FOUND, "Share not found").into_response();
        }
    };

    // Check if share is enabled
    if !share_config.enabled {
        warn!("Share '{}' is disabled", share_name);
        return (StatusCode::FORBIDDEN, "Share is disabled").into_response();
    }

    // Construct the full filesystem path
    let requested_path = share_config.path.join(file_path);

    // Security check: ensure the path is within the share directory
    let canonical_share_path = match fs::canonicalize(&share_config.path).await {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to canonicalize share path: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    let canonical_requested_path = match fs::canonicalize(&requested_path).await {
        Ok(p) => p,
        Err(_) => {
            // Path doesn't exist
            return (StatusCode::NOT_FOUND, "File or directory not found").into_response();
        }
    };

    if !canonical_requested_path.starts_with(&canonical_share_path) {
        warn!(
            "Path traversal attempt detected: {:?} not in {:?}",
            canonical_requested_path, canonical_share_path
        );
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    // Check if path is a directory or file
    let metadata = match fs::metadata(&canonical_requested_path).await {
        Ok(m) => m,
        Err(e) => {
            warn!(
                "Failed to get metadata for {:?}: {}",
                canonical_requested_path, e
            );
            return (StatusCode::NOT_FOUND, "File or directory not found").into_response();
        }
    };

    if metadata.is_dir() {
        // Check if browseable
        if !share_config.browseable {
            return (StatusCode::FORBIDDEN, "Directory listing disabled").into_response();
        }

        // Serve directory listing
        serve_directory_listing(
            share_name,
            file_path,
            &canonical_requested_path,
            share_config,
            &state.cache_dir,
        )
        .await
    } else {
        // Serve file
        serve_file(&canonical_requested_path, share_config).await
    }
}

async fn serve_directory_listing(
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

#[derive(Debug)]
struct DirEntry {
    name: String,
    is_dir: bool,
    size: u64,
    modified: Option<std::time::SystemTime>,
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

fn generate_directory_html(
    share_name: &str,
    relative_path: &str,
    entries: Vec<DirEntry>,
) -> String {
    let title = if relative_path.is_empty() {
        format!("Index of /{}", share_name)
    } else {
        format!("Index of /{}/{}", share_name, relative_path)
    };

    let parent_link = if !relative_path.is_empty() {
        let parent_path = if relative_path.contains('/') {
            relative_path.rsplitn(2, '/').nth(1).unwrap_or("")
        } else {
            ""
        };
        format!(
            r#"<tr><td><a href="/shares/{}/{}">📁 ..</a></td><td>-</td><td>-</td></tr>"#,
            share_name, parent_path
        )
    } else {
        String::new()
    };

    let mut rows = String::new();
    for entry in entries {
        let icon = if entry.is_dir { "📁" } else { "📄" };
        let size = if entry.is_dir {
            "-".to_string()
        } else {
            format_size(entry.size)
        };
        let modified = entry
            .modified
            .and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
            })
            .map(|ts| format_timestamp(ts))
            .unwrap_or_else(|| "-".to_string());

        let path_prefix = if relative_path.is_empty() {
            String::new()
        } else {
            format!("{}/", relative_path)
        };

        rows.push_str(&format!(
            r#"<tr><td><a href="/shares/{}/{}{}">{} {}</a></td><td>{}</td><td>{}</td></tr>"#,
            share_name,
            path_prefix,
            urlencoding::encode(&entry.name),
            icon,
            html_escape::encode_text(&entry.name),
            size,
            modified
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 2rem;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #161b22;
            border-radius: 6px;
            border: 1px solid #30363d;
            overflow: hidden;
        }}
        h1 {{
            padding: 1.5rem 2rem;
            background: #161b22;
            border-bottom: 1px solid #30363d;
            font-size: 1.5rem;
            font-weight: 600;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            text-align: left;
            padding: 1rem 2rem;
            background: #0d1117;
            font-weight: 600;
            border-bottom: 1px solid #30363d;
        }}
        td {{
            padding: 0.75rem 2rem;
            border-bottom: 1px solid #21262d;
        }}
        tr:hover {{
            background: #0d1117;
        }}
        a {{
            color: #58a6ff;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .footer {{
            padding: 1rem 2rem;
            text-align: center;
            color: #8b949e;
            font-size: 0.875rem;
            border-top: 1px solid #30363d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{}</h1>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Modified</th>
                </tr>
            </thead>
            <tbody>
                {}
                {}
            </tbody>
        </table>
        <div class="footer">
            Stratus File Server
        </div>
    </div>
</body>
</html>"#,
        html_escape::encode_text(&title),
        html_escape::encode_text(&title),
        parent_link,
        rows
    )
} // TODO: Move this to a separate HTML template file

fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

fn format_timestamp(timestamp: u64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp(timestamp as i64, 0);
    match dt {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "-".to_string(),
    }
}

async fn serve_file(file_path: &PathBuf, _share_config: &ShareConfig) -> Response {
    // Read file
    let contents = match fs::read(file_path).await {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to read file {:?}: {}", file_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read file").into_response();
        }
    };

    // Determine content type
    let content_type = mime_guess::from_path(file_path)
        .first_or_octet_stream()
        .to_string();

    // Get filename for Content-Disposition
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download");

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CONTENT_DISPOSITION,
                format!(r#"inline; filename="{}""#, filename),
            ),
        ],
        contents,
    )
        .into_response()
}
