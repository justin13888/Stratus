use axum::{
    body::Body,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use std::path::PathBuf;
use tokio::fs;
use tokio_util::io::ReaderStream;
use tracing::warn;

use crate::config::ShareConfig;

pub async fn serve_file(file_path: &PathBuf, _share_config: &ShareConfig) -> Response {
    // Get file metadata for Content-Length
    let metadata = match fs::metadata(file_path).await {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to get file metadata {:?}: {}", file_path, e);
            return (StatusCode::NOT_FOUND, "File not found").into_response();
        }
    };

    // Open file for streaming
    let file = match tokio::fs::File::open(file_path).await {
        Ok(f) => f,
        Err(e) => {
            warn!("Failed to open file {:?}: {}", file_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to open file").into_response();
        }
    };

    // Create a stream with optimal buffer size (64KB chunks)
    let stream = ReaderStream::with_capacity(file, 64 * 1024);
    let body = Body::from_stream(stream);

    // Determine content type
    let content_type = mime_guess::from_path(file_path)
        .first_or_octet_stream()
        .to_string();

    // Get filename for Content-Disposition
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download");

    // Use inline disposition for better browser preview support
    let disposition = format!(r#"inline; filename="{}""#, filename);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_DISPOSITION, disposition),
            (header::CONTENT_LENGTH, metadata.len().to_string()),
            (header::ACCEPT_RANGES, "bytes".to_string()),
        ],
        body,
    )
        .into_response()
}
