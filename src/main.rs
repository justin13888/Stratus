use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use axum::http::StatusCode;
use axum::{Router, routing::get};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use eyre::{Result, eyre};
use listenfd::ListenFd;
use std::net::TcpListener;
use tokio::sync::Semaphore;
use tower::ServiceBuilder;
use tower::timeout::TimeoutLayer;
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, decompression::RequestDecompressionLayer,
};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod shares;

use config::ServerConfig;
use shares::ShareState;

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
        EnvFilter::new(format!("stratus={log_level},tower_http=debug,axum=debug"))
    });

    // Initialize tracing with optional file logging
    if let Some(log_file) = &logging_config.file {
        // File logging enabled
        let file_appender = tracing_appender::rolling::daily(
            log_file
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
            log_file
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("stratus.log")),
        );
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(false)
                    .with_span_list(true)
                    .with_writer(non_blocking),
            )
            .with(env_filter)
            .init();

        // Keep the guard alive for the lifetime of the program
        std::mem::forget(_guard);

        info!("File logging enabled: {:?}", log_file);
    } else {
        // Console logging only
        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(false)
                    .with_span_list(true),
            )
            .with(env_filter)
            .init();
    }

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

    // Determine working directory
    let workdir = server_settings
        .workdir
        .as_deref()
        .unwrap_or_else(|| Path::new("."));

    // Create working directory if it doesn't exist
    std::fs::create_dir_all(workdir)
        .map_err(|e| eyre!("Failed to create working directory {:?}: {}", workdir, e))?;

    info!("Working directory: {:?}", workdir);

    // TODO: Implement TLS configuration based on tls_config settings (min_version, ocsp_stapling, client_cert_mode)
    let rustls_config = RustlsConfig::from_pem_file(&tls_config.cert_file, &tls_config.key_file)
        .await
        .map_err(|e| eyre!("Failed to load TLS certificates: {}", e))?;

    // Build the application with configured middleware
    let app = build_app(&security_config, &network_config, &shares, workdir)?;

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
            // Configure TCP socket options
            let listener = TcpListener::bind(bind_addr)
                .map_err(|e| eyre!("Failed to bind to {}: {}", bind_addr, e))?;

            // Note: TCP socket options (TCP_NODELAY, keepalive, backlog) need to be set at a lower level
            // std::net::TcpListener doesn't expose these methods directly
            // For production use, consider using the socket2 crate for fine-grained control
            // TODO: Use socket2 crate to set tcp_nodelay, tcp_keepalive, and listen_backlog before bind

            info!("Binding to {}", bind_addr);
            listener
        }
    };

    info!("Server listening on {}", listener.local_addr().unwrap());

    // TODO: Implement per-connection semaphore limiting
    // Currently axum-server doesn't provide hooks for per-connection middleware
    // Would need to wrap the make_service with custom connection tracking
    let _connection_limit = Arc::new(Semaphore::new(network_config.max_connections));
    info!(
        "Max connections configured: {} (enforcement not yet implemented)",
        network_config.max_connections
    );

    // Create shutdown signal handler
    let handle = Handle::new();
    let shutdown_handle = handle.clone();

    // Spawn a task to listen for shutdown signals
    tokio::spawn(async move {
        // Wait for Ctrl+C or SIGTERM
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C signal");
            }
            _ = terminate => {
                info!("Received SIGTERM signal");
            }
        }

        info!(
            "Starting graceful shutdown with timeout of {}s",
            network_config.connection_timeout
        );
        shutdown_handle
            .graceful_shutdown(Some(Duration::from_secs(network_config.connection_timeout)));
    });

    // Start the server with connection limiting
    let server = axum_server::from_tcp_rustls(listener, rustls_config).handle(handle);

    // Wrap the service to enforce connection limits
    let make_service = app.into_make_service();

    info!("Server ready to accept connections");

    server
        .serve(make_service)
        .await
        .map_err(|e| eyre!("Server error: {}", e))?;

    Ok(())
}

fn build_app(
    security_config: &config::SecurityConfig,
    network_config: &config::NetworkConfig,
    shares: &HashMap<String, config::ShareConfig>,
    workdir: &Path,
) -> Result<Router> {
    // Initialize share state
    let cache_dir = workdir.join("cache");
    let share_state = ShareState::new(shares.clone(), cache_dir);

    // Create share router with state
    let share_router = Router::new()
        .route("/shares/{*path}", get(shares::serve_share))
        .with_state(share_state);

    // Create base router with health and index endpoints
    let mut app = Router::new()
        .route("/health", get(health_handler))
        .merge(share_router);

    // Log enabled shares
    if !shares.is_empty() {
        info!("Share endpoints mounted at /shares/{{*path}}");

        for (name, share_config) in shares {
            if !share_config.enabled {
                info!("Share '{}' is disabled, skipping", name);
                continue;
            }

            info!(
                "Share '{}' enabled: {:?} (browseable={}, read_only={})",
                name, share_config.path, share_config.browseable, share_config.read_only
            );
        }
    }

    // TODO: Implement write operations (currently read-only)
    // TODO: Implement authentication based on read_list, write_list, admin_list, deny_list
    // TODO: Implement guest_ok handling
    // TODO: Implement max_connections per share
    // TODO: Implement versioning if enabled
    // TODO: Implement max_file_size enforcement on uploads
    // TODO: Implement file_locking

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

    // Add request timeout with error handling
    let request_timeout = Duration::from_secs(network_config.request_timeout);
    app = app.layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|_: tower::BoxError| async {
                StatusCode::REQUEST_TIMEOUT
            }))
            .layer(TimeoutLayer::new(request_timeout)),
    );
    info!("Request timeout: {}s", network_config.request_timeout);

    // TODO: Implement request body size limiting based on network_config.max_request_size
    // Requires custom middleware or tower-http "limit" feature

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

async fn health_handler() -> StatusCode {
    StatusCode::OK // TODO: Check actual health status
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use http::StatusCode;
    use tower::ServiceExt;

    use super::*;

    // Helper to create a test app
    fn test_app() -> Router {
        Router::new()
            .route("/health", get(health_handler))
            .layer(RequestDecompressionLayer::new())
            .layer(CompressionLayer::new())
            .layer(CorsLayer::permissive())
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let request = http::Request::get("/health").body(Body::empty()).unwrap();

        let response = test_app().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
// TODO: Add unit testing for all config implementations
