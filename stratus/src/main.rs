use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use axum::http::StatusCode;
use axum::{Router, routing::get};
use axum_server::Handle;
use eyre::{Result, eyre};
use listenfd::ListenFd;
use tracing::{error, info, warn};

mod auth;
mod cert;
mod config;
mod errors;
mod logging;
mod metrics;
mod middleware;
mod network;
mod shares;
mod tls;
mod vfs;

#[cfg(test)]
mod test_utils;

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
    let config = ServerConfig::from_file("./config.toml")?;

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
    logging::init_logger(&logging_config)?;

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

    // Auto-generate self-signed certificate if configured and cert/key are missing
    if let Err(e) = cert::maybe_generate_cert(&tls_config) {
        return Err(eyre!("Failed to auto-generate TLS certificate: {}", e));
    }

    // Configure TLS
    let rustls_config = tls::configure_rustls(&tls_config).await?;

    // Start TLS cert hot-reloader
    if let Err(e) = tls::start_cert_watcher(rustls_config.clone(), tls_config.clone()) {
        warn!("Failed to start TLS cert watcher: {}", e);
        warn!("TLS certificates will not be hot-reloaded on changes");
    } else {
        info!("TLS cert hot-reloading enabled");
    }

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
            // Configure socket with custom options
            network::configure_socket(bind_addr, &network_config)?
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

    // Start the server. MtlsAcceptor wraps RustlsAcceptor and injects the
    // peer certificate (if present) as a PeerCertificate request extension,
    // which MtlsAuthProvider reads. When mTLS is not configured the extension
    // is simply absent and basic auth continues to work normally.
    let server = axum_server::Server::from_tcp(listener)
        .acceptor(tls::MtlsAcceptor::new(rustls_config))
        .handle(handle);

    // Use into_make_service_with_connect_info so that ConnectInfo<SocketAddr> is
    // available as a request extension (required by rate limiting and auth middleware)
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();

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

    // Create auth brute-force rate limiter if auth lockout is configured
    let auth_rate_limiter = {
        use auth::rate_limit::{AuthRateLimitConfig, AuthRateLimiter};
        use std::sync::Arc;
        use std::time::Duration;
        let limiter_config = AuthRateLimitConfig {
            lockout_threshold: security_config.auth_lockout_threshold,
            initial_lockout: Duration::from_secs(security_config.auth_lockout_duration),
            backoff_multiplier: security_config.auth_lockout_multiplier,
            max_lockout: Duration::from_secs(security_config.auth_lockout_max_duration),
        };
        Arc::new(AuthRateLimiter::new(limiter_config))
    };

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

    // Apply middleware stack using the middleware module
    let middleware_config = middleware::MiddlewareConfig::from_app_config(
        security_config,
        network_config,
        metrics_config,
        server_name,
    );

    let auth_provider_opt = if security_config.auth_required {
        Some(auth_provider)
    } else {
        None
    };

    app = middleware::apply_middleware(
        app,
        middleware_config,
        auth_provider_opt,
        Some(auth_rate_limiter),
    );

    // TODO: Implement access logging if logging_config.access_log is enabled

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
    use tower_http::{
        compression::CompressionLayer, cors::CorsLayer, decompression::RequestDecompressionLayer,
    };

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
