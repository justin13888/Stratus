use std::net::SocketAddr;

use axum::{Router, routing::get};
use axum_server::tls_rustls::RustlsConfig;
use eyre::{Result, eyre};
use listenfd::ListenFd;
use std::net::TcpListener;
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, decompression::RequestDecompressionLayer,
};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod config;

use config::ServerConfig;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    // Load environment variables from .env file if present
    dotenvy::dotenv().ok();

    // Load configuration first
    let config = ServerConfig::from_file("./config.toml").map_err(|e| eyre!(e))?; // TODO: Fetch config path from CLI arg or env

    let ServerConfig {
        server: server_settings,
        tls: tls_config,
        http2: http_config,
        logging: logging_config,
        network: network_config,
        security: security_config,
        shares,
    } = config;

    // Initialize logging based on config
    let log_level = match logging_config.level {
        config::LogLevel::Trace => "trace",
        config::LogLevel::Debug => "debug",
        config::LogLevel::Info => "info",
        config::LogLevel::Warn => "warn",
        config::LogLevel::Error => "error",
    };

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!("stratus={},tower_http=debug,axum=debug", log_level))
    });

    // TODO: Implement file logging if logging_config.file is set
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .json()
                .with_current_span(false)
                .with_span_list(true),
        )
        .with(env_filter)
        .init();

    info!("Configuration loaded successfully");
    info!(
        "Server: {}:{}",
        server_settings.bind_address, server_settings.port
    );
    info!(
        "TLS: min_version={:?}, ocsp_stapling={}",
        tls_config.min_version, tls_config.ocsp_stapling
    );
    info!(
        "HTTP/2: max_concurrent_streams={}, keepalive={}s",
        http_config.max_concurrent_streams, http_config.keepalive_interval
    );
    info!(
        "Network: max_connections={}, timeout={}s",
        network_config.max_connections, network_config.connection_timeout
    );
    info!(
        "Security: auth_required={}, compression={}",
        security_config.auth_required, security_config.compression_enabled
    );
    info!("Shares: {} configured", shares.len());

    // TODO: Implement TLS configuration based on tls_config settings (min_version, ocsp_stapling, client_cert_mode)
    let rustls_config = RustlsConfig::from_pem_file(&tls_config.cert_file, &tls_config.key_file)
        .await
        .map_err(|e| eyre!("Failed to load TLS certificates: {}", e))?;

    // TODO: Implement HTTP/2 settings configuration (initial_connection_window_size, initial_stream_window_size, etc.)
    // axum-server doesn't expose HTTP/2 settings directly, may need to use hyper directly or accept defaults

    // Build the application with configured middleware
    let app = build_app(&security_config, &shares)?;

    // Determine bind address
    let bind_addr = SocketAddr::from((server_settings.bind_address, server_settings.port));

    // Check for systemfd listener first
    let mut listenfd = ListenFd::from_env();
    let listener = match listenfd.take_tcp_listener(0).unwrap() {
        Some(listener) => {
            info!("Using systemfd listener");
            listener.set_nonblocking(true).unwrap();
            listener
        }
        None => {
            // TODO: Implement TCP socket options (tcp_keepalive, tcp_nodelay, listen_backlog)
            info!("Binding to {}", bind_addr);
            TcpListener::bind(bind_addr)
                .map_err(|e| eyre!("Failed to bind to {}: {}", bind_addr, e))?
        }
    };

    info!("Server listening on {}", listener.local_addr().unwrap());

    // TODO: Implement graceful shutdown with connection timeout from config
    // TODO: Implement max_connections limiting
    // TODO: Implement connection timeout and request timeout

    axum_server::from_tcp_rustls(listener, rustls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| eyre!("Server error: {}", e))?;

    Ok(())
}

fn build_app(
    security_config: &config::SecurityConfig,
    shares: &std::collections::HashMap<String, config::ShareConfig>,
) -> Result<Router> {
    // TODO: Implement share routing based on shares config
    // Each share should get its own route with appropriate handlers

    let mut app = Router::new().route("/", get(handler));

    // Add share routes
    for (name, share_config) in shares {
        if !share_config.enabled {
            info!("Share '{}' is disabled, skipping", name);
            continue;
        }

        let mount_point = share_config
            .mount_point
            .clone()
            .unwrap_or_else(|| format!("/{}", name));

        info!(
            "Mounting share '{}' at {} -> {:?}",
            name, mount_point, share_config.path
        );

        // TODO: Implement file serving handlers for each share
        // TODO: Implement browseable/listing if enabled
        // TODO: Implement read_only enforcement
        // TODO: Implement authentication based on read_list, write_list, admin_list, deny_list
        // TODO: Implement guest_ok handling
        // TODO: Implement max_connections per share
        // TODO: Implement hide_dot_files filtering
        // TODO: Implement follow_symlinks setting
        // TODO: Implement exclude_patterns and include_patterns filtering
        // TODO: Implement versioning if enabled
        // TODO: Implement max_file_size enforcement on uploads
        // TODO: Implement file_locking
    }

    // Apply middleware layers based on security config
    // Build middleware stack conditionally
    app = app.layer(RequestDecompressionLayer::new());

    // Add compression if enabled
    if security_config.compression_enabled {
        // TODO: Configure compression algorithms based on security_config.compression_algorithms
        // TODO: Configure compression_min_size
        // Currently tower-http doesn't expose min_size configuration easily
        app = app.layer(CompressionLayer::new());
    }

    // TODO: Implement request body size limiting based on network_config.max_request_size
    // Requires tower-http "limit" feature which isn't available, may need custom middleware

    // Configure CORS if enabled
    if security_config.cors_enabled {
        let cors = if security_config.cors_allowed_origins.is_empty() {
            // Allow all origins
            CorsLayer::permissive()
        } else {
            // TODO: Configure specific allowed origins from cors_allowed_origins
            // tower-http CorsLayer::new() requires proper origin parsing
            CorsLayer::permissive() // Using permissive for now
        };
        app = app.layer(cors);
    }

    // TODO: Implement authentication middleware based on security_config.auth_required and auth_method
    // TODO: Implement rate limiting if security_config.rate_limiting_enabled
    // TODO: Implement access logging if logging_config.access_log is enabled

    Ok(app)
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

    // Helper to create a test app
    fn test_app() -> Router {
        Router::new()
            .route("/", get(handler))
            .layer(RequestDecompressionLayer::new())
            .layer(CompressionLayer::new())
            .layer(CorsLayer::permissive())
    }

    // TODO: Add tests for downloading file with compression
    #[tokio::test]
    async fn fetch_index_gzip() {
        // Given
        let request = http::Request::get("/")
            .header(header::ACCEPT_ENCODING, "gzip")
            .body(Body::empty())
            .unwrap();

        // When

        let response = test_app().oneshot(request).await.unwrap();

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
        let response = test_app().oneshot(request).await.unwrap();

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
