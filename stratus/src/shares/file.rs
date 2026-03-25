use axum::{
    body::Body,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::path::PathBuf;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
use tracing::warn;

use crate::config::ShareConfig;
use crate::errors::ShareError;
use crate::vfs::Vfs;

/// Stream chunk size for file responses.
/// 64 KiB balances per-chunk memory overhead against the number of read syscalls.
const FILE_STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Serve a single file from the VFS.
///
/// `_share_config` is reserved for future per-share enforcement (e.g. `max_file_size`).
/// Authorization is already applied before this call in `serve_share()`.
pub async fn serve_file<V: Vfs>(
    file_path: &PathBuf,
    _share_config: &ShareConfig,
    headers: HeaderMap,
    vfs: &V,
) -> Response {
    let start = Instant::now();

    // Get file metadata for Content-Length
    let metadata = match vfs.metadata(file_path).await {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to get file metadata {:?}: {}", file_path, e);
            crate::metrics::record_file_operation("read_metadata", start.elapsed());
            let err = ShareError::PathNotFound(file_path.to_path_buf());
            return (StatusCode::NOT_FOUND, err.to_string()).into_response();
        }
    };

    crate::metrics::record_file_operation("read_metadata", start.elapsed());

    let file_size = metadata.len;

    // Check for Range header and parse it
    let range = headers
        .get(header::RANGE)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            // Parse range header using proper parser
            http_range_header::parse_range_header(h)
                .ok()
                .and_then(|parsed| {
                    // Validate against file size and get ranges
                    parsed.validate(file_size).ok()
                })
                .and_then(|ranges| {
                    // Only handle single ranges (not multipart)
                    if ranges.len() == 1 {
                        let r = &ranges[0];
                        Some((*r.start(), *r.end()))
                    } else {
                        None
                    }
                })
        });

    // Open file for streaming
    let open_start = Instant::now();
    let mut file = match vfs.open(file_path).await {
        Ok(f) => f,
        Err(e) => {
            warn!("Failed to open file {:?}: {}", file_path, e);
            crate::metrics::record_file_operation("open", open_start.elapsed());
            let err = ShareError::FileReadError(format!("Failed to open file: {}", e));
            return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
        }
    };
    crate::metrics::record_file_operation("open", open_start.elapsed());

    // Determine content type
    let content_type = mime_guess::from_path(file_path)
        .first_or_octet_stream()
        .to_string();

    // Get filename for Content-Disposition
    let filename = vfs
        .file_name(file_path)
        .unwrap_or_else(|| "download".to_string());

    // Use inline disposition for better browser preview support
    let disposition = format!(r#"inline; filename="{}""#, filename);

    match range {
        Some((start, end)) => {
            // Serve partial content
            let content_length = end - start + 1;

            // Seek to start position
            if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
                warn!("Failed to seek in file {:?}: {}", file_path, e);
                let err = ShareError::FileReadError(format!("Failed to seek in file: {}", e));
                return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
            }

            // Take only the requested range
            let limited_file = file.take(content_length);
            let stream = ReaderStream::with_capacity(limited_file, FILE_STREAM_CHUNK_BYTES);
            let body = Body::from_stream(stream);

            let content_range = format!("bytes {}-{}/{}", start, end, file_size);

            (
                StatusCode::PARTIAL_CONTENT,
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CONTENT_DISPOSITION, disposition),
                    (header::CONTENT_LENGTH, content_length.to_string()),
                    (header::CONTENT_RANGE, content_range),
                    (header::ACCEPT_RANGES, "bytes".to_string()),
                ],
                body,
            )
                .into_response()
        }
        None => {
            // Serve full file
            // Create a stream with optimal buffer size (64KB chunks)
            let stream = ReaderStream::with_capacity(file, FILE_STREAM_CHUNK_BYTES);
            let body = Body::from_stream(stream);

            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CONTENT_DISPOSITION, disposition),
                    (header::CONTENT_LENGTH, file_size.to_string()),
                    (header::ACCEPT_RANGES, "bytes".to_string()),
                ],
                body,
            )
                .into_response()
        }
    }
}
