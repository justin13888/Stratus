// Middleware stack configuration for the Stratus web server
//
// This module provides a clean separation of middleware setup from the main
// application routing, making it easier to:
// - Test middleware composition
// - Understand the middleware stack
// - Add/remove middleware layers
// - Configure middleware based on application config

use axum::http::{HeaderValue, Response, StatusCode};
use axum::{Router, middleware as axum_middleware};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceBuilder;
use tower::limit::ConcurrencyLimitLayer;
use tower::timeout::TimeoutLayer;
use tower_http::{
    compression::{CompressionLayer, predicate::SizeAbove},
    cors::{AllowOrigin, CorsLayer},
    decompression::RequestDecompressionLayer,
    limit::RequestBodyLimitLayer,
};
use tracing::info;

use crate::{auth, config, metrics};

/// Configuration for building the middleware stack
pub struct MiddlewareConfig {
    // Security settings
    pub auth_required: bool,
    pub cors_enabled: bool,
    pub cors_allowed_origins: Vec<String>,
    pub compression_enabled: bool,
    pub compression_algorithms: Vec<config::CompressionAlgorithm>,
    pub compression_min_size: usize, // in KB

    // Network settings
    pub max_connections: usize,
    pub request_timeout: u64,    // in seconds
    pub max_request_size: usize, // in MB

    // Metrics
    pub metrics_enabled: bool,

    // Server identification
    pub server_name: String,
}

impl MiddlewareConfig {
    /// Create middleware config from application config
    pub fn from_app_config(
        security: &config::SecurityConfig,
        network: &config::NetworkConfig,
        metrics: &config::MetricsConfig,
        server_name: &str,
    ) -> Self {
        Self {
            auth_required: security.auth_required,
            cors_enabled: security.cors_enabled,
            cors_allowed_origins: security.cors_allowed_origins.clone(),
            compression_enabled: security.compression_enabled,
            compression_algorithms: security.compression_algorithms.clone(),
            compression_min_size: security.compression_min_size,
            max_connections: network.max_connections,
            request_timeout: network.request_timeout,
            max_request_size: network.max_request_size,
            metrics_enabled: metrics.enabled,
            server_name: server_name.to_string(),
        }
    }
}

/// Apply all middleware layers to a router based on configuration
pub fn apply_middleware(
    app: Router,
    config: MiddlewareConfig,
    auth_provider: Option<Arc<dyn auth::AuthProvider + Send + Sync>>,
) -> Router {
    let mut app = app;

    // Layer 1: Request decompression (handles compressed client requests)
    app = app.layer(RequestDecompressionLayer::new());

    // Layer 2: Request body size limiting
    let max_body_size = config.max_request_size * 1024 * 1024; // Convert MB to bytes
    app = app.layer(RequestBodyLimitLayer::new(max_body_size));
    info!("Request body size limit: {} MB", config.max_request_size);

    // Layer 3: Response compression (if enabled)
    if config.compression_enabled {
        app = apply_compression(app, &config);
        info!(
            "Compression enabled with algorithms: {:?}, min size: {} KB",
            config.compression_algorithms, config.compression_min_size
        );
    }

    // Layer 4: Request timeout
    app = apply_timeout(app, config.request_timeout);
    info!("Request timeout: {}s", config.request_timeout);

    // Layer 5: CORS (if enabled)
    if config.cors_enabled {
        app = apply_cors(app, &config.cors_allowed_origins);
        if config.cors_allowed_origins.is_empty() {
            info!("CORS enabled with permissive mode (all origins allowed)");
        } else {
            info!(
                "CORS configured with specific origins: {:?}",
                config.cors_allowed_origins
            );
        }
    }

    // Layer 6: Authentication (if required)
    if config.auth_required
        && let Some(provider) = auth_provider
    {
        app = apply_auth(app, provider);
        info!("Authentication middleware enabled");
    }

    // Layer 7: Server header
    app = apply_server_header(app, &config.server_name);

    // Layer 8: Metrics tracking (if enabled)
    if config.metrics_enabled {
        app = apply_metrics(app);
        info!("Metrics tracking middleware enabled");
    }

    // Layer 9: Connection limit
    app = app.layer(ConcurrencyLimitLayer::new(config.max_connections));
    info!("Max concurrent requests limit: {}", config.max_connections);

    app
}

/// Apply compression middleware with configured algorithms and minimum size
fn apply_compression(app: Router, config: &MiddlewareConfig) -> Router {
    // Check which algorithms are enabled
    let has_gzip = config
        .compression_algorithms
        .contains(&config::CompressionAlgorithm::Gzip);
    let has_br = config
        .compression_algorithms
        .contains(&config::CompressionAlgorithm::Br);
    let has_zstd = config
        .compression_algorithms
        .contains(&config::CompressionAlgorithm::Zstd);

    // Configure compression layer with specific algorithms
    let compression = CompressionLayer::new()
        .gzip(has_gzip)
        .br(has_br)
        .zstd(has_zstd);

    // Only compress responses larger than the configured minimum size
    let min_size_bytes = config.compression_min_size * 1024; // Convert KB to bytes
    let min_size = min_size_bytes.min(u16::MAX as usize) as u16;
    let predicate = SizeAbove::new(min_size);

    app.layer(compression.compress_when(predicate))
}

/// Apply request timeout middleware with error handling
fn apply_timeout(app: Router, timeout_seconds: u64) -> Router {
    let request_timeout = Duration::from_secs(timeout_seconds);
    app.layer(
        ServiceBuilder::new()
            .layer(axum::error_handling::HandleErrorLayer::new(
                |_: tower::BoxError| async { StatusCode::REQUEST_TIMEOUT },
            ))
            .layer(TimeoutLayer::new(request_timeout)),
    )
}

/// Apply CORS middleware with configured origins
fn apply_cors(app: Router, allowed_origins: &[String]) -> Router {
    let cors = if allowed_origins.is_empty() {
        // Allow all origins
        CorsLayer::permissive()
    } else {
        // Configure specific allowed origins
        let origins: Vec<HeaderValue> = allowed_origins
            .iter()
            .filter_map(|origin| origin.parse().ok())
            .collect();

        if origins.is_empty() {
            // If parsing failed for all origins, fall back to permissive
            CorsLayer::permissive()
        } else {
            CorsLayer::new().allow_origin(AllowOrigin::list(origins))
        }
    };

    app.layer(cors)
}

/// Apply authentication middleware
fn apply_auth(app: Router, auth_provider: Arc<dyn auth::AuthProvider + Send + Sync>) -> Router {
    let auth_middleware = auth::AuthMiddleware::new(auth_provider);
    app.layer(axum_middleware::from_fn(move |req, next| {
        auth_middleware.clone().authenticate(req, next)
    }))
}

/// Apply Server header middleware
fn apply_server_header(app: Router, server_name: &str) -> Router {
    let server_name_arc = Arc::new(server_name.to_string());
    app.layer(axum_middleware::map_response(
        move |mut response: Response<_>| {
            let server_name = Arc::clone(&server_name_arc);
            async move {
                response.headers_mut().insert(
                    axum::http::header::SERVER,
                    HeaderValue::from_str(&server_name)
                        .unwrap_or_else(|_| HeaderValue::from_static("Stratus")),
                );
                response
            }
        },
    ))
}

/// Apply metrics tracking middleware
fn apply_metrics(app: Router) -> Router {
    app.layer(axum_middleware::from_fn(metrics::track_metrics))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::SecurityConfigBuilder;
    use axum::http::Request;
    use axum::{Router, body::Body, routing::get};
    use tower::ServiceExt;

    // Helper to create test router
    fn test_router() -> Router {
        Router::new().route("/test", get(|| async { "test response" }))
    }

    #[tokio::test]
    async fn test_apply_server_header() {
        let app = apply_server_header(test_router(), "TestServer/1.0");

        let response = app
            .oneshot(Request::get("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            response.headers().get(axum::http::header::SERVER).unwrap(),
            "TestServer/1.0"
        );
    }

    #[tokio::test]
    async fn test_apply_cors_permissive() {
        let app = apply_cors(test_router(), &[]);

        let response = app
            .oneshot(Request::get("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // Permissive CORS should add headers
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_apply_cors_specific_origins() {
        let app = apply_cors(test_router(), &["https://example.com".to_string()]);

        let response = app
            .oneshot(
                Request::get("/test")
                    .header("Origin", "https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should have CORS headers for allowed origin
        let allow_origin = response.headers().get("access-control-allow-origin");
        assert!(allow_origin.is_some());
    }

    #[tokio::test]
    async fn test_middleware_config_from_app_config() {
        use crate::config::{MetricsConfig, NetworkConfig};

        let security = SecurityConfigBuilder::new().cors_enabled(true).build();
        let network = NetworkConfig::default();
        let metrics = MetricsConfig::default();

        let mw_config =
            MiddlewareConfig::from_app_config(&security, &network, &metrics, "TestServer/1.0");

        assert!(mw_config.compression_enabled);
        assert!(mw_config.cors_enabled);
        assert_eq!(mw_config.server_name, "TestServer/1.0");
    }

    #[tokio::test]
    async fn test_apply_compression_disabled() {
        let config = MiddlewareConfig {
            auth_required: false,
            cors_enabled: false,
            cors_allowed_origins: vec![],
            compression_enabled: false,
            compression_algorithms: vec![],
            compression_min_size: 1,
            max_connections: 100,
            request_timeout: 30,
            max_request_size: 10,
            metrics_enabled: false,
            server_name: "Test".to_string(),
        };

        let app = apply_middleware(test_router(), config, None);

        let response = app
            .oneshot(Request::get("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // Should get a response without compression (small body)
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_apply_compression_enabled() {
        let config = MiddlewareConfig {
            auth_required: false,
            cors_enabled: false,
            cors_allowed_origins: vec![],
            compression_enabled: true,
            compression_algorithms: vec![
                config::CompressionAlgorithm::Gzip,
                config::CompressionAlgorithm::Br,
            ],
            compression_min_size: 1, // 1 KB minimum
            max_connections: 100,
            request_timeout: 30,
            max_request_size: 10,
            metrics_enabled: false,
            server_name: "Test".to_string(),
        };

        let app = apply_middleware(test_router(), config, None);

        let response = app
            .oneshot(
                Request::get("/test")
                    .header("Accept-Encoding", "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
