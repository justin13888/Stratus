pub use state::ShareState;

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::{debug, info, trace, warn};

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

    // Enforce per-share connection limit (holds the permit for the duration of this handler)
    let _permit = if let Some(sem) = state.semaphores.get(share_name) {
        match Arc::clone(sem).acquire_owned().await {
            Ok(permit) => Some(permit),
            Err(_) => {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        }
    } else {
        None
    };

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

/// Lexically normalize a path by resolving `.` and `..` components without
/// touching the filesystem. This is used to detect path-traversal in write
/// operations where the target file does not yet exist.
fn normalize_path(path: &std::path::Path) -> std::path::PathBuf {
    use std::path::Component;
    let mut result = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            c => result.push(c),
        }
    }
    result
}

/// Handle `PUT /shares/{share_name}/{*path}` — upload or overwrite a file.
///
/// Returns `201 Created` for new files, `204 No Content` for overwrites.
/// Requires write permission on the share. Enforces `max_file_size` when set.
pub async fn upload_file<V: Vfs>(
    State(state): State<ShareState<V>>,
    Path(path_parts): Path<String>,
    request: Request,
) -> Response {
    // Clone user before consuming `request` for the body
    let user: Option<crate::auth::User> = get_authenticated_user(&request).cloned();
    let body: Bytes = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Parse path: "{share_name}/{file_path}"
    let parts: Vec<&str> = path_parts.splitn(2, '/').collect();
    let share_name = parts[0];
    let file_path = if parts.len() > 1 { parts[1] } else { "" };

    if file_path.is_empty() {
        return (StatusCode::BAD_REQUEST, "Cannot upload to share root").into_response();
    }

    // Look up share
    let share_config = match state.shares.get(share_name) {
        Some(cfg) => cfg,
        None => {
            let err = ShareError::NotFound(share_name.to_string());
            return (StatusCode::NOT_FOUND, err.to_string()).into_response();
        }
    };

    if !share_config.enabled {
        let err = ShareError::Disabled(share_name.to_string());
        return (StatusCode::FORBIDDEN, err.to_string()).into_response();
    }

    if share_config.read_only {
        return (StatusCode::FORBIDDEN, "Share is read-only").into_response();
    }

    if !authz::check_permission(user.as_ref(), share_config, authz::Permission::Write) {
        warn!(
            "User {:?} denied write access to share '{}'",
            user.as_ref().map(|u| &u.username),
            share_name
        );
        crate::metrics::record_share_request(share_name, 0, false);
        let err = ShareError::AccessDenied(share_name.to_string());
        return (StatusCode::FORBIDDEN, err.to_string()).into_response();
    }

    // Acquire per-share connection semaphore
    let _permit = if let Some(sem) = state.semaphores.get(share_name) {
        match Arc::clone(sem).acquire_owned().await {
            Ok(p) => Some(p),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        None
    };

    // Enforce per-share max_file_size (0 = unlimited)
    if share_config.max_file_size > 0 && body.len() as u64 > share_config.max_file_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "File size {} exceeds share limit of {} bytes",
                body.len(),
                share_config.max_file_size
            ),
        )
            .into_response();
    }

    // --- Path security validation ---
    // Canonicalize the share root (resolves any symlinks in the share path itself)
    let canonical_share_path = match state.vfs.canonicalize(&share_config.path).await {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to canonicalize share path: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    // Build the target path and lexically normalize to catch `..` traversal
    let target = normalize_path(&canonical_share_path.join(file_path));
    if !target.starts_with(&canonical_share_path) {
        warn!(
            "Upload path traversal attempt: {:?} escapes {:?}",
            target, canonical_share_path
        );
        return (StatusCode::FORBIDDEN, "Path traversal attempt").into_response();
    }

    // Ensure parent directory exists (create if needed) then re-validate via
    // canonicalize to catch any symlink-based escape in intermediate dirs.
    let parent = match target.parent() {
        Some(p) => p.to_path_buf(),
        None => return (StatusCode::BAD_REQUEST, "Invalid path").into_response(),
    };
    if let Err(e) = state.vfs.create_dir_all(&parent).await {
        warn!("Failed to create parent directories for {:?}: {}", target, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create parent directory",
        )
            .into_response();
    }
    match state.vfs.canonicalize(&parent).await {
        Ok(canonical_parent) if canonical_parent.starts_with(&canonical_share_path) => {}
        Ok(canonical_parent) => {
            warn!(
                "Upload parent {:?} resolves outside share {:?}",
                canonical_parent, canonical_share_path
            );
            return (StatusCode::FORBIDDEN, "Path escapes share root").into_response();
        }
        Err(e) => {
            warn!("Failed to canonicalize parent {:?}: {}", parent, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }

    // Check if file already exists (determines response code)
    let file_exists = state.vfs.metadata(&target).await.is_ok();

    // Write the file
    if let Err(e) = state.vfs.write(&target, &body).await {
        warn!("Failed to write {:?}: {}", target, e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to write file").into_response();
    }

    info!(
        "User {:?} uploaded {} bytes to share '{}' path {:?}",
        user.as_ref().map(|u| &u.username),
        body.len(),
        share_name,
        target
    );
    crate::metrics::record_share_request(share_name, body.len() as u64, true);

    if file_exists {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::CREATED.into_response()
    }
}

/// Handle `DELETE /shares/{share_name}/{*path}` — delete a file or directory.
///
/// Directories are deleted recursively. Requires write permission on the share.
/// Returns `204 No Content` on success.
pub async fn delete_share_item<V: Vfs>(
    State(state): State<ShareState<V>>,
    Path(path_parts): Path<String>,
    request: Request,
) -> Response {
    let user = get_authenticated_user(&request);

    let parts: Vec<&str> = path_parts.splitn(2, '/').collect();
    let share_name = parts[0];
    let file_path = if parts.len() > 1 { parts[1] } else { "" };

    if file_path.is_empty() {
        return (StatusCode::BAD_REQUEST, "Cannot delete share root").into_response();
    }

    let share_config = match state.shares.get(share_name) {
        Some(cfg) => cfg,
        None => {
            let err = ShareError::NotFound(share_name.to_string());
            return (StatusCode::NOT_FOUND, err.to_string()).into_response();
        }
    };

    if !share_config.enabled {
        let err = ShareError::Disabled(share_name.to_string());
        return (StatusCode::FORBIDDEN, err.to_string()).into_response();
    }

    if share_config.read_only {
        return (StatusCode::FORBIDDEN, "Share is read-only").into_response();
    }

    if !authz::check_permission(user, share_config, authz::Permission::Write) {
        warn!(
            "User {:?} denied delete access to share '{}'",
            user.map(|u| &u.username),
            share_name
        );
        crate::metrics::record_share_request(share_name, 0, false);
        let err = ShareError::AccessDenied(share_name.to_string());
        return (StatusCode::FORBIDDEN, err.to_string()).into_response();
    }

    let _permit = if let Some(sem) = state.semaphores.get(share_name) {
        match Arc::clone(sem).acquire_owned().await {
            Ok(p) => Some(p),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        None
    };

    // Path validation (same as serve_share — file must exist)
    let requested_path = state.vfs.join(&share_config.path, file_path);
    let canonical_share_path = match state.vfs.canonicalize(&share_config.path).await {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to canonicalize share path: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    let metadata = match state.vfs.metadata(&requested_path).await {
        Ok(m) => m,
        Err(_) => return (StatusCode::NOT_FOUND, "File or directory not found").into_response(),
    };

    if metadata.is_symlink && !share_config.follow_symlinks {
        return (StatusCode::FORBIDDEN, "Symlink access denied").into_response();
    }

    let is_within_base = match state
        .vfs
        .validate_path_within_base(&requested_path, &canonical_share_path)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("Path validation error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };
    if !is_within_base {
        warn!(
            "Delete path traversal attempt: {:?} escapes {:?}",
            requested_path, canonical_share_path
        );
        return (StatusCode::FORBIDDEN, "Path traversal attempt").into_response();
    }

    // Perform deletion
    let result = if metadata.is_dir {
        state.vfs.remove_dir_all(&requested_path).await
    } else {
        state.vfs.remove_file(&requested_path).await
    };

    match result {
        Ok(()) => {
            info!(
                "User {:?} deleted {:?} from share '{}'",
                user.map(|u| &u.username),
                requested_path,
                share_name
            );
            crate::metrics::record_share_request(share_name, 0, true);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            warn!("Failed to delete {:?}: {}", requested_path, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Delete failed").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::{Router, body::Body, routing::get};
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{AuthenticatedUser, User};
    use crate::test_utils::ShareConfigBuilder;
    use crate::vfs::backend::LocalFs;

    fn make_router(shares: HashMap<String, crate::config::ShareConfig>, cache_dir: std::path::PathBuf) -> Router {
        let vfs = LocalFs::new();
        let state = ShareState::new(shares, cache_dir, vfs);
        Router::new()
            .route(
                "/shares/{*path}",
                get(serve_share::<LocalFs>)
                    .put(upload_file::<LocalFs>)
                    .delete(delete_share_item::<LocalFs>),
            )
            .with_state(state)
    }

    #[tokio::test]
    async fn test_serve_share_not_found() {
        let cache = tempfile::tempdir().unwrap();
        let router = make_router(HashMap::new(), cache.path().to_path_buf());
        let req = Request::get("/shares/noexist/file.txt").body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_serve_share_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        shares.insert(
            "myshare".to_string(),
            ShareConfigBuilder::new(dir.path()).enabled(false).build(),
        );
        let router = make_router(shares, cache.path().to_path_buf());
        let req = Request::get("/shares/myshare/").body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_serve_share_guest_ok_anonymous_access() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello").unwrap();
        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        shares.insert(
            "pub".to_string(),
            ShareConfigBuilder::new(dir.path()).guest_ok(true).build(),
        );
        let router = make_router(shares, cache.path().to_path_buf());
        let req = Request::get("/shares/pub/hello.txt").body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_serve_share_auth_required_no_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        shares.insert(
            "private".to_string(),
            ShareConfigBuilder::new(dir.path()).guest_ok(false).build(),
        );
        let router = make_router(shares, cache.path().to_path_buf());
        let req = Request::get("/shares/private/").body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        // No user in extensions, guest_ok=false → Forbidden (no auth middleware in test stack)
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_serve_share_authenticated_user_read_access() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secret.txt"), "data").unwrap();
        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        shares.insert(
            "restricted".to_string(),
            ShareConfigBuilder::new(dir.path())
                .guest_ok(false)
                .with_read_access(vec!["alice"])
                .build(),
        );
        let router = make_router(shares, cache.path().to_path_buf());
        let mut req = Request::get("/shares/restricted/secret.txt")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(AuthenticatedUser(User::new("alice".to_string())));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_serve_share_symlink_outside_share_denied() {
        let share_dir = tempfile::tempdir().unwrap();
        let target_dir = tempfile::tempdir().unwrap();
        std::fs::write(target_dir.path().join("secret.txt"), "outside").unwrap();
        // Create a symlink inside share pointing outside
        let link_path = share_dir.path().join("link");
        std::os::unix::fs::symlink(target_dir.path(), &link_path).unwrap();

        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        shares.insert(
            "share".to_string(),
            ShareConfigBuilder::new(share_dir.path())
                .guest_ok(true)
                .follow_symlinks(false)
                .build(),
        );
        let router = make_router(shares, cache.path().to_path_buf());
        let req = Request::get("/shares/share/link/secret.txt")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_serve_share_directory_listing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("readme.md"), "# hi").unwrap();
        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        shares.insert(
            "docs".to_string(),
            ShareConfigBuilder::new(dir.path()).guest_ok(true).build(),
        );
        let router = make_router(shares, cache.path().to_path_buf());
        // Request the share root (directory)
        let req = Request::get("/shares/docs/").body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers()[axum::http::header::CONTENT_TYPE]
            .to_str()
            .unwrap();
        assert!(ct.contains("text/html"), "expected HTML directory listing, got {ct}");
    }

    // ---- Upload (PUT) tests ----

    #[tokio::test]
    async fn test_upload_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        shares.insert(
            "rw".to_string(),
            ShareConfigBuilder::new(dir.path())
                .guest_ok(false)
                .read_only(false)
                .build(),
        );
        let router = make_router(shares, cache.path().to_path_buf());
        let mut req = Request::put("/shares/rw/new_file.txt")
            .body(Body::from("hello"))
            .unwrap();
        req.extensions_mut()
            .insert(AuthenticatedUser(User::new("alice".to_string())));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(std::fs::read(dir.path().join("new_file.txt")).unwrap(), b"hello");
    }

    #[tokio::test]
    async fn test_upload_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("existing.txt"), "old content").unwrap();
        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        shares.insert(
            "rw".to_string(),
            ShareConfigBuilder::new(dir.path())
                .guest_ok(false)
                .read_only(false)
                .build(),
        );
        let router = make_router(shares, cache.path().to_path_buf());
        let mut req = Request::put("/shares/rw/existing.txt")
            .body(Body::from("new content"))
            .unwrap();
        req.extensions_mut()
            .insert(AuthenticatedUser(User::new("alice".to_string())));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("existing.txt")).unwrap(),
            "new content"
        );
    }

    #[tokio::test]
    async fn test_upload_denied_on_readonly_share() {
        let dir = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        shares.insert(
            "ro".to_string(),
            ShareConfigBuilder::new(dir.path())
                .guest_ok(false)
                .read_only(true)
                .build(),
        );
        let router = make_router(shares, cache.path().to_path_buf());
        let mut req = Request::put("/shares/ro/file.txt")
            .body(Body::from("data"))
            .unwrap();
        req.extensions_mut()
            .insert(AuthenticatedUser(User::new("alice".to_string())));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_upload_enforces_max_file_size() {
        let dir = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        let mut cfg = ShareConfigBuilder::new(dir.path())
            .guest_ok(false)
            .read_only(false)
            .build();
        cfg.max_file_size = 4; // 4-byte limit
        shares.insert("limited".to_string(), cfg);
        let router = make_router(shares, cache.path().to_path_buf());
        let mut req = Request::put("/shares/limited/file.txt")
            .body(Body::from("hello")) // 5 bytes > 4
            .unwrap();
        req.extensions_mut()
            .insert(AuthenticatedUser(User::new("alice".to_string())));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ---- Delete tests ----

    #[tokio::test]
    async fn test_delete_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("to_delete.txt"), "gone").unwrap();
        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        shares.insert(
            "rw".to_string(),
            ShareConfigBuilder::new(dir.path())
                .guest_ok(false)
                .read_only(false)
                .build(),
        );
        let router = make_router(shares, cache.path().to_path_buf());
        let mut req = Request::delete("/shares/rw/to_delete.txt")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(AuthenticatedUser(User::new("alice".to_string())));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(!dir.path().join("to_delete.txt").exists());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_returns_404() {
        let dir = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        shares.insert(
            "rw".to_string(),
            ShareConfigBuilder::new(dir.path())
                .guest_ok(false)
                .read_only(false)
                .build(),
        );
        let router = make_router(shares, cache.path().to_path_buf());
        let mut req = Request::delete("/shares/rw/phantom.txt")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(AuthenticatedUser(User::new("alice".to_string())));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_denied_on_readonly_share() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), "data").unwrap();
        let cache = tempfile::tempdir().unwrap();
        let mut shares = HashMap::new();
        shares.insert(
            "ro".to_string(),
            ShareConfigBuilder::new(dir.path())
                .guest_ok(false)
                .read_only(true)
                .build(),
        );
        let router = make_router(shares, cache.path().to_path_buf());
        let mut req = Request::delete("/shares/ro/file.txt")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(AuthenticatedUser(User::new("alice".to_string())));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
