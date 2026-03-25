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
mod watcher;

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

    // Initialize Prometheus metrics exporter
    let metrics_handle = init_metrics_exporter(&metrics_config);

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
    let rustls_config = tls::configure_rustls(&tls_config)?;

    // Start TLS cert hot-reloader
    if let Err(e) = tls::start_cert_watcher(rustls_config.clone(), tls_config.clone()) {
        warn!("Failed to start TLS cert watcher: {}", e);
        warn!("TLS certificates will not be hot-reloaded on changes");
    } else {
        info!("TLS cert hot-reloading enabled");
    }

    // Determine metrics server placement (separate vs. main server)
    let main_bind_addr = SocketAddr::from((server_settings.bind_address, server_settings.port));
    let (metrics_bind_addr, use_separate_metrics_server) =
        resolve_metrics_server(&metrics_config, main_bind_addr, &metrics_handle);

    // Spawn a separate plain-HTTP metrics server if configured
    if use_separate_metrics_server {
        let metrics_addr = metrics_bind_addr.unwrap();
        spawn_metrics_server(
            metrics_addr,
            main_bind_addr,
            metrics_config.endpoint.clone(),
            metrics_handle.as_ref().unwrap().clone(),
        );
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

    let listener = acquire_listener(main_bind_addr, &network_config)?;
    info!("Server listening on {}", listener.local_addr().unwrap());

    // Create shutdown signal handler
    let handle = Handle::new();
    spawn_shutdown_handler(handle.clone(), network_config.connection_timeout);

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

/// Initialise the Prometheus metrics exporter if metrics are enabled.
/// Returns `None` (with a warning) if initialisation fails.
fn init_metrics_exporter(
    config: &config::MetricsConfig,
) -> Option<metrics_exporter_prometheus::PrometheusHandle> {
    if !config.enabled {
        return None;
    }
    match metrics::init_metrics_exporter() {
        Ok(handle) => {
            info!("Metrics collection enabled at {}", config.endpoint);
            Some(handle)
        }
        Err(e) => {
            warn!("Failed to initialize metrics exporter: {}", e);
            None
        }
    }
}

/// Determine whether metrics should be served on a separate server and, if so,
/// what address that server should bind to.
///
/// Returns `(metrics_bind_addr, use_separate_server)`.
fn resolve_metrics_server(
    config: &config::MetricsConfig,
    main_addr: SocketAddr,
    handle: &Option<metrics_exporter_prometheus::PrometheusHandle>,
) -> (Option<SocketAddr>, bool) {
    let metrics_addr = if config.enabled {
        let addr = config.bind_address.unwrap_or(main_addr.ip());
        let port = config.port.unwrap_or(main_addr.port());
        Some(SocketAddr::from((addr, port)))
    } else {
        None
    };

    let use_separate = if let (Some(addr), Some(_)) = (metrics_addr, handle) {
        // A separate server is only warranted when the operator has explicitly
        // configured a different address or port AND the result differs from main.
        let explicitly_configured = config.bind_address.is_some() || config.port.is_some();
        explicitly_configured && addr != main_addr
    } else {
        false
    };

    (metrics_addr, use_separate)
}

/// Spawn a plain-HTTP server that serves only the Prometheus metrics endpoint.
fn spawn_metrics_server(
    metrics_addr: SocketAddr,
    main_addr: SocketAddr,
    endpoint: String,
    handle: metrics_exporter_prometheus::PrometheusHandle,
) {
    info!(
        "Starting separate metrics server on {} (main server: {})",
        metrics_addr, main_addr
    );

    tokio::spawn(async move {
        let metrics_router = Router::new()
            .route(&endpoint, get(metrics::metrics_handler))
            .with_state(handle);

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
}

/// Obtain a bound TCP listener, preferring a systemfd-passed socket (for
/// zero-downtime dev reloads) and falling back to a freshly configured socket.
fn acquire_listener(
    bind_addr: SocketAddr,
    network_config: &config::NetworkConfig,
) -> Result<std::net::TcpListener> {
    let mut listenfd = ListenFd::from_env();
    match listenfd
        .take_tcp_listener(0)
        .map_err(|e| eyre!("Failed to check systemfd listener: {}", e))?
    {
        Some(listener) => {
            info!("Using systemfd listener");
            listener
                .set_nonblocking(true)
                .map_err(|e| eyre!("Failed to set listener non-blocking: {}", e))?;
            Ok(listener)
        }
        None => network::configure_socket(bind_addr, network_config),
    }
}

/// Spawn a task that waits for SIGINT or SIGTERM and then initiates a graceful
/// shutdown with the configured connection drain timeout.
fn spawn_shutdown_handler(handle: Handle, connection_timeout: u64) {
    tokio::spawn(async move {
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
            _ = ctrl_c => { info!("Received Ctrl+C signal"); }
            _ = terminate => { info!("Received SIGTERM signal"); }
        }

        info!(
            "Starting graceful shutdown with timeout of {}s",
            connection_timeout
        );
        handle.graceful_shutdown(Some(Duration::from_secs(connection_timeout)));
    });
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
    // Authorization based on read_list, write_list, admin_list, deny_list is enforced
    // per-request in serve_share() via shares::authz::check_permission().
    // guest_ok is handled in shares::authz::check_permission().
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
