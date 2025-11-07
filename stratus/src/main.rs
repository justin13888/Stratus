use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use axum::http::StatusCode;
use axum::response::Response;
use axum::{Router, routing::get};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use eyre::{Result, eyre};
use listenfd::ListenFd;
use std::net::TcpListener;
use tower::ServiceBuilder;
use tower::limit::ConcurrencyLimitLayer;
use tower::timeout::TimeoutLayer;
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, decompression::RequestDecompressionLayer,
    limit::RequestBodyLimitLayer,
};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod config;
mod metrics;
mod shares;
mod vfs;

use config::ServerConfig;
use shares::ShareState;

struct MetricsContext {
    handle: Option<metrics_exporter_prometheus::PrometheusHandle>,
    use_separate_server: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    // Load environment variables from .env file if present
    dotenvy::dotenv().ok();

    // Load configuration first
    let config = ServerConfig::from_file("./config.toml").map_err(|e| eyre!(e))?;

    let ServerConfig {
        server: server_settings,
        tls: tls_config,
        http2: http_config,
        logging: logging_config,
        metrics: metrics_config,
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
    info!("Metrics: enabled={}", metrics_config.enabled);

    // Initialize metrics exporter if enabled
    let metrics_handle = if metrics_config.enabled {
        match metrics::init_metrics_exporter() {
            Ok(handle) => {
                info!("Metrics collection enabled at {}", metrics_config.endpoint);
                Some(handle)
            }
            Err(e) => {
                warn!("Failed to initialize metrics exporter: {}", e);
                None
            }
        }
    } else {
        None
    };

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

    // Determine metrics server address - use explicit config or default to main server address
    let metrics_bind_addr = if metrics_config.enabled {
        let metrics_addr = metrics_config
            .bind_address
            .unwrap_or(server_settings.bind_address);
        let metrics_port = metrics_config.port.unwrap_or(server_settings.port);
        Some(SocketAddr::from((metrics_addr, metrics_port)))
    } else {
        None
    };

    // Determine if we need a separate metrics server
    let main_bind_addr = SocketAddr::from((server_settings.bind_address, server_settings.port));
    let use_separate_metrics_server =
        if let (Some(metrics_addr), Some(_handle)) = (metrics_bind_addr, &metrics_handle) {
            // Only start separate server if the address is different from main server
            // OR if either bind_address or port was explicitly configured (not both None)
            let explicitly_configured =
                metrics_config.bind_address.is_some() || metrics_config.port.is_some();
            let different_address = metrics_addr != main_bind_addr;

            explicitly_configured && different_address
        } else {
            false
        };

    // Spawn separate metrics server if needed
    if use_separate_metrics_server {
        let metrics_addr = metrics_bind_addr.unwrap();
        let metrics_endpoint = metrics_config.endpoint.clone();
        let metrics_handle_clone = metrics_handle.as_ref().unwrap().clone();

        info!(
            "Starting separate metrics server on {} (main server: {})",
            metrics_addr, main_bind_addr
        );

        tokio::spawn(async move {
            let metrics_router = Router::new()
                .route(&metrics_endpoint, get(metrics::metrics_handler))
                .with_state(metrics_handle_clone);

            let listener = match tokio::net::TcpListener::bind(metrics_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind metrics server to {}: {}", metrics_addr, e);
                    return;
                }
            };

            info!("Metrics server listening on {}", metrics_addr);

            if let Err(e) = axum::serve(listener, metrics_router).await {
                error!("Metrics server error: {}", e);
            }
        });
    } else if metrics_config.enabled && metrics_handle.is_some() {
        info!(
            "Metrics will be served on main server at {}{}",
            main_bind_addr, metrics_config.endpoint
        );
    }

    // Build the application with configured middleware
    let app = build_app(
        &server_settings.server_name,
        &security_config,
        &network_config,
        &metrics_config,
        MetricsContext {
            handle: metrics_handle,
            use_separate_server: use_separate_metrics_server,
        },
        &shares,
        workdir,
    )?;

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
            // Use socket2 for fine-grained TCP socket configuration
            use socket2::{Domain, Protocol, Socket, Type};

            let socket = Socket::new(
                Domain::for_address(bind_addr),
                Type::STREAM,
                Some(Protocol::TCP),
            )
            .map_err(|e| eyre!("Failed to create socket: {}", e))?;

            // Set TCP_NODELAY if configured
            if network_config.tcp_nodelay {
                socket
                    .set_nodelay(true)
                    .map_err(|e| eyre!("Failed to set TCP_NODELAY: {}", e))?;
                info!("TCP_NODELAY enabled");
            }

            // Set TCP keepalive if configured
            if network_config.tcp_keepalive {
                use socket2::TcpKeepalive;
                let keepalive = TcpKeepalive::new()
                    .with_time(Duration::from_secs(network_config.tcp_keepalive_interval));
                socket
                    .set_tcp_keepalive(&keepalive)
                    .map_err(|e| eyre!("Failed to set TCP keepalive: {}", e))?;
                info!(
                    "TCP keepalive enabled with interval: {}s",
                    network_config.tcp_keepalive_interval
                );
            }

            // Set SO_REUSEADDR for easier restarts
            socket
                .set_reuse_address(true)
                .map_err(|e| eyre!("Failed to set SO_REUSEADDR: {}", e))?;

            // Bind the socket
            socket
                .bind(&bind_addr.into())
                .map_err(|e| eyre!("Failed to bind to {}: {}", bind_addr, e))?;

            // Listen with configured backlog
            socket
                .listen(network_config.listen_backlog as i32)
                .map_err(|e| eyre!("Failed to listen: {}", e))?;

            info!(
                "Binding to {} with listen backlog: {}",
                bind_addr, network_config.listen_backlog
            );

            // Set non-blocking mode
            socket
                .set_nonblocking(true)
                .map_err(|e| eyre!("Failed to set non-blocking: {}", e))?;

            // Convert socket2::Socket to std::net::TcpListener
            TcpListener::from(socket)
        }
    };

    info!("Server listening on {}", listener.local_addr().unwrap());

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
    server_name: &str,
    security_config: &config::SecurityConfig,
    network_config: &config::NetworkConfig,
    metrics_config: &config::MetricsConfig,
    metrics_ctx: MetricsContext,
    shares: &HashMap<String, config::ShareConfig>,
    workdir: &Path,
) -> Result<Router> {
    // Initialize share state with LocalFs backend
    let cache_dir = workdir.join("cache");
    let vfs = vfs::backend::LocalFs::new();
    let share_state = ShareState::new(shares.clone(), cache_dir, vfs);

    // Create authentication provider
    let auth_provider = auth::create_auth_provider(security_config)?;
    info!(
        "Authentication: enabled={}, method={:?}",
        security_config.auth_required, security_config.auth_method
    );

    // Create share router with state
    let share_router = Router::new()
        .route("/shares/{*path}", get(shares::serve_share))
        .with_state(share_state);

    // Create base router with health and index endpoints
    let mut app = Router::new().route("/health", get(health_handler));

    // Add metrics endpoint if enabled and NOT using separate server
    if metrics_config.enabled
        && let Some(handle) = metrics_ctx.handle
        && !metrics_ctx.use_separate_server
    {
        let metrics_router = Router::new()
            .route(&metrics_config.endpoint, get(metrics::metrics_handler))
            .with_state(handle);
        app = app.merge(metrics_router);
        info!("Metrics endpoint mounted at {}", metrics_config.endpoint);
    }

    // Merge share router
    app = app.merge(share_router);

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
    // TODO: Implement authorization based on read_list, write_list, admin_list, deny_list
    // TODO: Implement guest_ok handling
    // TODO: Implement max_connections per share
    // TODO: Implement versioning if enabled
    // TODO: Implement max_file_size enforcement on uploads
    // TODO: Implement file_locking

    // Apply middleware layers based on security config
    // Build middleware stack conditionally
    app = app.layer(RequestDecompressionLayer::new());

    // Add request body size limiting
    let max_body_size = network_config.max_request_size * 1024 * 1024; // Convert MB to bytes
    app = app.layer(RequestBodyLimitLayer::new(max_body_size));
    info!(
        "Request body size limit: {} MB",
        network_config.max_request_size
    );

    // Add compression if enabled with smart predicates
    if security_config.compression_enabled {
        use tower_http::compression::predicate::SizeAbove;

        // Enable only configured algorithms
        let has_gzip = security_config
            .compression_algorithms
            .contains(&config::CompressionAlgorithm::Gzip);
        let has_br = security_config
            .compression_algorithms
            .contains(&config::CompressionAlgorithm::Br);
        let has_zstd = security_config
            .compression_algorithms
            .contains(&config::CompressionAlgorithm::Zstd);

        // Configure compression layer with specific algorithms
        let compression = CompressionLayer::new()
            .gzip(has_gzip)
            .br(has_br)
            .zstd(has_zstd);

        // Only compress responses larger than the configured minimum size
        // Note: SizeAbove expects a u16, so we clamp to u16::MAX to avoid overflow
        let min_size_bytes = security_config.compression_min_size * 1024; // Convert KB to bytes
        let min_size = min_size_bytes.min(u16::MAX as usize) as u16;
        let predicate = SizeAbove::new(min_size);

        app = app.layer(compression.compress_when(predicate));
        info!(
            "Compression enabled with algorithms: {:?}, min size: {} KB",
            security_config.compression_algorithms, security_config.compression_min_size
        );
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

    // Configure CORS if enabled
    if security_config.cors_enabled {
        let cors = if security_config.cors_allowed_origins.is_empty() {
            // Allow all origins
            CorsLayer::permissive()
        } else {
            // Configure specific allowed origins
            use tower_http::cors::AllowOrigin;

            let origins: Vec<_> = security_config
                .cors_allowed_origins
                .iter()
                .filter_map(|origin| origin.parse::<axum::http::HeaderValue>().ok())
                .collect();

            if origins.is_empty() {
                // If parsing failed for all origins, fall back to permissive
                info!("Failed to parse CORS origins, using permissive mode");
                CorsLayer::permissive()
            } else {
                info!(
                    "CORS configured with specific origins: {:?}",
                    security_config.cors_allowed_origins
                );
                CorsLayer::new().allow_origin(AllowOrigin::list(origins))
            }
        };
        app = app.layer(cors);
    }

    // Add authentication middleware if required
    if security_config.auth_required {
        let auth_middleware = auth::AuthMiddleware::new(Arc::clone(&auth_provider));
        app = app.layer(axum::middleware::from_fn(move |req, next| {
            auth_middleware.clone().authenticate(req, next)
        }));
        info!(
            "Authentication middleware enabled (method: {:?})",
            security_config.auth_method
        );
    }

    // TODO: Implement rate limiting if security_config.rate_limiting_enabled
    // TODO: Implement access logging if logging_config.access_log is enabled

    // Add Server header middleware
    let server_name_arc = Arc::new(server_name.to_string());
    app = app.layer(axum::middleware::map_response(
        move |mut response: Response| {
            let server_name = Arc::clone(&server_name_arc);
            async move {
                response.headers_mut().insert(
                    axum::http::header::SERVER,
                    axum::http::HeaderValue::from_str(&server_name)
                        .unwrap_or_else(|_| axum::http::HeaderValue::from_static("Stratus")),
                );
                response
            }
        },
    ));

    // Add metrics tracking middleware if enabled
    if metrics_config.enabled {
        app = app.layer(axum::middleware::from_fn(metrics::track_metrics));
        info!("Metrics tracking middleware enabled");
    }

    // Apply global connection limit
    app = app.layer(ConcurrencyLimitLayer::new(network_config.max_connections));
    info!(
        "Max concurrent requests limit: {}",
        network_config.max_connections
    );

    Ok(app)
}

// TODO: Add unit tests to verify share endpoints expose compression headers &&

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
