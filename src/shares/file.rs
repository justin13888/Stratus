use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use std::path::PathBuf;
use tokio::fs;
use tracing::warn;

use crate::config::ShareConfig;

pub async fn serve_file(file_path: &PathBuf, _share_config: &ShareConfig) -> Response {
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

    // Use attachment disposition to force download when appropriate
    let disposition = format!(r#"inline; filename="{}""#, filename);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        contents,
    )
        .into_response()
}
