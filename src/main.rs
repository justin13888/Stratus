use std::{net::SocketAddr, path::PathBuf};

use axum::{Router, routing::get};
use axum_server::tls_rustls::RustlsConfig;
use eyre::{Result, eyre};
use listenfd::ListenFd;
use std::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, decompression::RequestDecompressionLayer,
};
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    // Load environment variables from .env file if present
    dotenvy::dotenv().ok();

    // Initialize JSON logging
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .json()
                .with_current_span(false)
                .with_span_list(true),
        )
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("stratus=info,tower_http=debug,axum=debug")),
        )
        .init();

    // // Load configuration
    // let config = Config::from_env().map_err(|e| eyre!(e))?;
    // info!("Configuration loaded: {:?}", config);

    // Ensure configured directories exist
    // TODO

    // Load TLS certificates
    let tls_config = RustlsConfig::from_pem_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cert.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("key.pem"),
    )
    .await
    .expect("Failed to load TLS certificates"); // TODO: Load from config

    let app = app();

    let mut listenfd = ListenFd::from_env();
    let listener = match listenfd.take_tcp_listener(0).unwrap() {
        // if we are given a tcp listener on listen fd 0, we use that one
        Some(listener) => {
            listener.set_nonblocking(true).unwrap();
            listener
        }
        // otherwise fall back to local listening
        None => TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 3000))).unwrap(), // TODO: Load from config
    };

    info!("Listening on {}", listener.local_addr().unwrap());

    axum_server::from_tcp_rustls(listener, tls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| eyre!("Server error: {}", e))?;

    Ok(())
}

fn app() -> Router {
    Router::new()
        .route("/", get(handler))
        .layer(
            ServiceBuilder::new()
                .layer(RequestDecompressionLayer::new())
                .layer(CompressionLayer::new()),
        )
        .layer(CorsLayer::permissive())
}

use axum::response::Html;
async fn handler() -> Html<String> {
    // Make the response larger to trigger compression (tower-http has a minimum size threshold)
    Html("<h1>Hello, World!</h1>".repeat(100))
} // TODO: Remove this

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use flate2::read::GzDecoder;
    use http::{StatusCode, header};
    use std::io::Read;
    use tower::ServiceExt;

    use super::*;

    // TODO: Add tests for downloading file with compression
    #[tokio::test]
    async fn fetch_index_gzip() {
        // Given
        let request = http::Request::get("/")
            .header(header::ACCEPT_ENCODING, "gzip")
            .body(Body::empty())
            .unwrap();

        // When

        let response = app().oneshot(request).await.unwrap();

        // Then

        assert_eq!(response.status(), StatusCode::OK);

        // Check if the response is compressed
        let content_encoding = response.headers().get(header::CONTENT_ENCODING);
        assert!(
            content_encoding.is_some(),
            "Content-Encoding header should be present"
        );
        assert_eq!(
            content_encoding.unwrap(),
            "gzip",
            "Content-Encoding should be gzip"
        );

        let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let mut decoder = GzDecoder::new(response_body.as_ref());
        let mut decompress_body = String::new();
        decoder.read_to_string(&mut decompress_body).unwrap();

        // Verify the decompressed body matches what the handler returns
        assert!(decompress_body.contains("<h1>Hello, World!</h1>"));
        assert!(decompress_body.len() > 100, "Should have repeated content");
    }

    #[tokio::test]
    async fn fetch_index_zstd() {
        // Given
        let request = http::Request::get("/")
            .header(header::ACCEPT_ENCODING, "zstd")
            .body(Body::empty())
            .unwrap();

        // When
        let response = app().oneshot(request).await.unwrap();

        // Then
        assert_eq!(response.status(), StatusCode::OK);

        // Check if the response is compressed
        let content_encoding = response.headers().get(header::CONTENT_ENCODING);
        assert!(
            content_encoding.is_some(),
            "Content-Encoding header should be present"
        );
        assert_eq!(
            content_encoding.unwrap(),
            "zstd",
            "Content-Encoding should be zstd"
        );

        let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let decompressed = zstd::decode_all(response_body.as_ref()).unwrap();
        let decompress_body = String::from_utf8(decompressed).unwrap();

        // Verify the decompressed body matches what the handler returns
        assert!(decompress_body.contains("<h1>Hello, World!</h1>"));
        assert!(decompress_body.len() > 100, "Should have repeated content");
    }
}
