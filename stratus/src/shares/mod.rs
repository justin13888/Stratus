pub use state::ShareState;

use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::{debug, trace, warn};

use directory::serve_directory_listing;
use file::serve_file;

use crate::vfs::Vfs;
use crate::{auth::get_authenticated_user, errors::ShareError};

mod authz;
mod directory;
mod file;
mod html;
mod state;
mod utils;

/// Handle requests to /shares/{share_name}/**
pub async fn serve_share<V: Vfs>(
    State(state): State<ShareState<V>>,
    Path(path_parts): Path<String>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let user = get_authenticated_user(&request);
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
            let err = ShareError::NotFound(share_name.to_string());
            return (StatusCode::NOT_FOUND, err.to_string()).into_response();
        }
    };

    // Check if share is enabled
    if !share_config.enabled {
        warn!("Share '{}' is disabled", share_name);
        crate::metrics::record_share_request(share_name, 0, false);
        let err = ShareError::Disabled(share_name.to_string());
        return (StatusCode::FORBIDDEN, err.to_string()).into_response();
    }

    // Authorization check: verify user has at least read access
    if !authz::check_permission(user, share_config, authz::Permission::Read) {
        warn!(
            "User {:?} denied access to share '{}'",
            user.map(|u| &u.username),
            share_name
        );
        crate::metrics::record_share_request(share_name, 0, false);
        let err = ShareError::AccessDenied(share_name.to_string());
        return (StatusCode::FORBIDDEN, err.to_string()).into_response();
    }
    trace!(
        "User {:?} granted access to share '{}'",
        user.map(|u| &u.username),
        share_name
    );

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

    // First check: does the requested path exist?
    let metadata = match state.vfs.metadata(&requested_path).await {
        Ok(m) => m,
        Err(e) => {
            // Path doesn't exist or error accessing it
            warn!(
                "Failed to get metadata for share '{}' path {:?}: {}",
                share_name, requested_path, e
            );
            crate::metrics::record_share_request(share_name, 0, false);
            return (StatusCode::NOT_FOUND, "File or directory not found").into_response();
        }
    };

    // Security check for symlinks: If this is a symlink and follow_symlinks is disabled, deny access
    if metadata.is_symlink && !share_config.follow_symlinks {
        warn!(
            "Symlink access denied (follow_symlinks=false): {:?}",
            requested_path
        );
        crate::metrics::record_share_request(share_name, 0, false);
        return (StatusCode::FORBIDDEN, "Symlink access denied").into_response();
    }

    // Critical security check: Validate that the path (including symlink targets) stays within bounds
    let is_within_base = match state
        .vfs
        .validate_path_within_base(&requested_path, &canonical_share_path)
        .await
    {
        Ok(valid) => valid,
        Err(e) => {
            warn!("Failed to validate path {:?}: {}", requested_path, e);
            crate::metrics::record_share_request(share_name, 0, false);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    if !is_within_base {
        warn!(
            "Path traversal attempt detected: {:?} escapes {:?}",
            requested_path, canonical_share_path
        );
        crate::metrics::record_share_request(share_name, 0, false);
        let err = ShareError::PathTraversal {
            path: requested_path.to_path_buf(),
            base: canonical_share_path.to_path_buf(),
        };
        return (StatusCode::FORBIDDEN, err.to_string()).into_response();
    }

    // Now get the canonical path for actual file operations
    let canonical_requested_path = match state.vfs.canonicalize(&requested_path).await {
        Ok(p) => p,
        Err(e) => {
            // Shouldn't happen since we already checked metadata, but be safe
            warn!(
                "Failed to canonicalize share '{}' path {:?}: {}",
                share_name, requested_path, e
            );
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
            &canonical_share_path,
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
