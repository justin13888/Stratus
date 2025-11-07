pub use state::ShareState;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tracing::{debug, warn};

use directory::serve_directory_listing;
use file::serve_file;

use crate::vfs::Vfs;

mod directory;
mod file;
mod html;
mod state;
mod utils;

/// Handle requests to /shares/{share_name}/**
pub async fn serve_share<V: Vfs>(
    State(state): State<ShareState<V>>,
    Path(path_parts): Path<String>,
    headers: HeaderMap,
) -> Response {
    use std::time::Instant;

    let start = Instant::now();

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
            crate::metrics::record_share_request(share_name, 0, false);
            return (StatusCode::NOT_FOUND, "Share not found").into_response();
        }
    };

    // Check if share is enabled
    if !share_config.enabled {
        warn!("Share '{}' is disabled", share_name);
        crate::metrics::record_share_request(share_name, 0, false);
        return (StatusCode::FORBIDDEN, "Share is disabled").into_response();
    }

    // Construct the full filesystem path
    let requested_path = state.vfs.join(&share_config.path, file_path);

    // Security check: ensure the path is within the share directory
    let canonical_share_path = match state.vfs.canonicalize(&share_config.path).await {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to canonicalize share path: {}", e);
            crate::metrics::record_share_request(share_name, 0, false);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    let canonical_requested_path = match state.vfs.canonicalize(&requested_path).await {
        Ok(p) => p,
        Err(_) => {
            // Path doesn't exist
            crate::metrics::record_share_request(share_name, 0, false);
            return (StatusCode::NOT_FOUND, "File or directory not found").into_response();
        }
    };

    if !state
        .vfs
        .path_starts_with(&canonical_requested_path, &canonical_share_path)
    {
        warn!(
            "Path traversal attempt detected: {:?} not in {:?}",
            canonical_requested_path, canonical_share_path
        );
        crate::metrics::record_share_request(share_name, 0, false);
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    // Check if path is a directory or file
    let metadata = match state.vfs.metadata(&canonical_requested_path).await {
        Ok(m) => m,
        Err(e) => {
            warn!(
                "Failed to get metadata for {:?}: {}",
                canonical_requested_path, e
            );
            crate::metrics::record_file_operation("metadata", start.elapsed());
            crate::metrics::record_share_request(share_name, 0, false);
            return (StatusCode::NOT_FOUND, "File or directory not found").into_response();
        }
    };

    crate::metrics::record_file_operation("metadata", start.elapsed());

    let response = if metadata.is_dir {
        // Check if browseable
        if !share_config.browseable {
            crate::metrics::record_share_request(share_name, 0, false);
            return (StatusCode::FORBIDDEN, "Directory listing disabled").into_response();
        }

        // Serve directory listing
        serve_directory_listing(
            share_name,
            file_path,
            &canonical_requested_path,
            share_config,
            &state.cache_dir,
            &state.vfs,
        )
        .await
    } else {
        // Serve file
        serve_file(&canonical_requested_path, share_config, headers, &state.vfs).await
    };

    // Record metrics for successful requests
    // Note: We approximate bytes served as the file size for successful file requests
    let bytes_served = if !metadata.is_dir && response.status().is_success() {
        metadata.len
    } else {
        0
    };
    crate::metrics::record_share_request(share_name, bytes_served, response.status().is_success());

    response
}
