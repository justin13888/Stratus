// Middleware stack configuration for the Stratus web server
//
// This module provides a clean separation of middleware setup from the main
// application routing, making it easier to:
// - Test middleware composition
// - Understand the middleware stack
// - Add/remove middleware layers
// - Configure middleware based on application config

use axum::http::{HeaderName, HeaderValue, Response, StatusCode};
use axum::{
    Router,
    extract::{ConnectInfo, Request as AxumRequest},
    middleware as axum_middleware,
};
use governor::clock::{Clock, QuantaClock};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
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
use tracing::{info, warn};

use crate::{auth, config, metrics};

/// Configuration for building the middleware stack
pub struct MiddlewareConfig {
    // Security settings
    pub auth_required: bool,
    pub cors_enabled: bool,
    pub cors_allowed_origins: Vec<String>,
    pub compression_enabled: bool,
    pub compression_algorithms: Vec<config::CompressionAlgorithm>,
    pub compression_min_size: usize, // in bytes

    // Security headers
    pub hsts_enabled: bool,
    pub hsts_max_age: u64,
    pub hsts_include_subdomains: bool,
    pub hsts_preload: bool,

    // Rate limiting
    pub rate_limiting_enabled: bool,
    pub rate_limit: u32,         // requests per minute per IP
    pub rate_limit_burst: u32,   // extra burst requests allowed
    pub trust_proxy_headers: bool,

    // Network settings
    pub max_connections: usize,
    pub request_timeout: u64,    // in seconds
    pub max_request_size: usize, // in bytes

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
            hsts_enabled: security.hsts_enabled,
            hsts_max_age: security.hsts_max_age,
            hsts_include_subdomains: security.hsts_include_subdomains,
            hsts_preload: security.hsts_preload,
            rate_limiting_enabled: security.rate_limiting_enabled,
            rate_limit: security.rate_limit,
            rate_limit_burst: security.rate_limit_burst,
            trust_proxy_headers: security.trust_proxy_headers,
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
    auth_rate_limiter: Option<Arc<auth::AuthRateLimiter>>,
) -> Router {
    let mut app = app;

    // Layer 1: Request decompression (handles compressed client requests)
    app = app.layer(RequestDecompressionLayer::new());

    // Layer 2: Request body size limiting
    app = app.layer(RequestBodyLimitLayer::new(config.max_request_size));
    info!(
        "Request body size limit: {} bytes ({} MiB)",
        config.max_request_size,
        config.max_request_size / (1024 * 1024)
    );

    // Layer 3: Response compression (if enabled)
    if config.compression_enabled {
        app = apply_compression(app, &config);
        info!(
            "Compression enabled with algorithms: {:?}, min size: {} bytes",
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

    // Layer 5.5: Global per-IP rate limiting (fires before auth to protect against DoS)
    if config.rate_limiting_enabled {
        app = apply_rate_limiting(app, &config);
        info!(
            "Rate limiting enabled: {} req/min per IP (burst: {})",
            config.rate_limit, config.rate_limit_burst
        );
    }

    // Layer 6: Authentication (if required)
    if config.auth_required
        && let Some(provider) = auth_provider
    {
        app = apply_auth(app, provider, auth_rate_limiter);
        info!("Authentication middleware enabled");
    }

    // Layer 7: Server header
    app = apply_server_header(app, &config.server_name);

    // Layer 7.5: Security response headers (HSTS, CSP, X-Frame-Options, etc.)
    app = apply_security_headers(app, &config);

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
    let min_size = config.compression_min_size.min(u16::MAX as usize) as u16;
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
            // All configured origins failed to parse; use restrictive CORS rather than
            // silently falling back to permissive (which would allow all origins).
            warn!(
                "All configured CORS origins failed to parse — \
                 using restrictive CORS (no cross-origin requests allowed). \
                 Check your cors_allowed_origins configuration."
            );
            CorsLayer::new()
        } else {
            CorsLayer::new().allow_origin(AllowOrigin::list(origins))
        }
    };

    app.layer(cors)
}

/// Apply per-IP rate limiting middleware using a token-bucket algorithm (governor)
fn apply_rate_limiting(app: Router, config: &MiddlewareConfig) -> Router {
    // Build the rate limiter: N requests per minute with an optional burst allowance
    let per_minute = NonZeroU32::new(config.rate_limit).unwrap_or(NonZeroU32::new(60).unwrap());
    let burst = NonZeroU32::new(config.rate_limit_burst).unwrap_or(NonZeroU32::new(10).unwrap());
    let quota = Quota::per_minute(per_minute).allow_burst(burst);
    let limiter: Arc<DefaultKeyedRateLimiter<IpAddr>> = Arc::new(RateLimiter::keyed(quota));
    let trust_proxy = config.trust_proxy_headers;

    app.layer(axum_middleware::from_fn(move |request: AxumRequest, next: axum::middleware::Next| {
        let limiter = Arc::clone(&limiter);
        async move {
            // Extract client IP from ConnectInfo (populated by axum-server)
            // or from X-Forwarded-For if trust_proxy_headers is enabled
            let client_ip: Option<IpAddr> = if trust_proxy {
                request
                    .headers()
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.split(',').next())
                    .and_then(|s| s.trim().parse().ok())
                    .or_else(|| {
                        request
                            .extensions()
                            .get::<ConnectInfo<SocketAddr>>()
                            .map(|ci| ci.0.ip())
                    })
            } else {
                request
                    .extensions()
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|ci| ci.0.ip())
            };

            if let Some(ip) = client_ip {
                match limiter.check_key(&ip) {
                    Ok(()) => {}
                    Err(negative) => {
                        let wait_time = negative.wait_time_from(QuantaClock::default().now());
                        let retry_after = wait_time.as_secs().max(1).to_string();
                        warn!(ip = %ip, "Rate limit exceeded");
                        let mut response =
                            Response::new(axum::body::Body::from("Too many requests"));
                        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                        if let Ok(hv) = HeaderValue::from_str(&retry_after) {
                            response
                                .headers_mut()
                                .insert(axum::http::header::RETRY_AFTER, hv);
                        }
                        return response;
                    }
                }
            }

            next.run(request).await
        }
    }))
}

/// Apply authentication middleware
fn apply_auth(
    app: Router,
    auth_provider: Arc<dyn auth::AuthProvider + Send + Sync>,
    rate_limiter: Option<Arc<auth::AuthRateLimiter>>,
) -> Router {
    let mut auth_middleware = auth::AuthMiddleware::new(auth_provider);
    if let Some(limiter) = rate_limiter {
        auth_middleware = auth_middleware.with_rate_limiter(limiter);
    }
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

/// Apply security response headers middleware
///
/// Injects the following headers on every response:
/// - `Strict-Transport-Security` (HSTS) — HTTP downgrade prevention
/// - `X-Content-Type-Options: nosniff` — prevent MIME sniffing
/// - `X-Frame-Options: DENY` — clickjacking protection
/// - `Content-Security-Policy` — XSS/injection defence
/// - `Referrer-Policy` — limit referrer leakage
/// - `Permissions-Policy` — disable unused browser APIs
/// - `X-XSS-Protection: 0` — disable the legacy XSS auditor (CSP is the proper replacement)
fn apply_security_headers(app: Router, config: &MiddlewareConfig) -> Router {
    // Build the HSTS header value once, reuse it across requests
    let hsts_value: Option<HeaderValue> = if config.hsts_enabled {
        let mut hsts = format!("max-age={}", config.hsts_max_age);
        if config.hsts_include_subdomains {
            hsts.push_str("; includeSubDomains");
        }
        if config.hsts_preload {
            hsts.push_str("; preload");
        }
        HeaderValue::from_str(&hsts).ok()
    } else {
        None
    };

    app.layer(axum_middleware::map_response(
        move |mut response: Response<_>| {
            let hsts = hsts_value.clone();
            async move {
                let headers = response.headers_mut();

                if let Some(hsts_hv) = hsts {
                    headers.insert(axum::http::header::STRICT_TRANSPORT_SECURITY, hsts_hv);
                }
                headers.insert(
                    axum::http::header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                );
                headers.insert(
                    axum::http::header::X_FRAME_OPTIONS,
                    HeaderValue::from_static("DENY"),
                );
                headers.insert(
                    axum::http::header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static(
                        "default-src 'self'; \
                         style-src 'self' 'unsafe-inline'; \
                         script-src 'none'; \
                         frame-ancestors 'none'",
                    ),
                );
                headers.insert(
                    axum::http::header::REFERRER_POLICY,
                    HeaderValue::from_static("strict-origin-when-cross-origin"),
                );
                headers.insert(
                    HeaderName::from_static("permissions-policy"),
                    HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
                );
                // Explicitly disable the legacy XSS auditor; CSP is the modern replacement
                headers.insert(
                    axum::http::header::X_XSS_PROTECTION,
                    HeaderValue::from_static("0"),
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

    fn test_router() -> Router {
        Router::new().route("/test", get(|| async { "test response" }))
    }

    /// Base `MiddlewareConfig` for tests. Override only the fields under test.
    fn test_middleware_config() -> MiddlewareConfig {
        MiddlewareConfig {
            auth_required: false,
            cors_enabled: false,
            cors_allowed_origins: vec![],
            compression_enabled: false,
            compression_algorithms: vec![],
            compression_min_size: 1024,
            hsts_enabled: false,
            hsts_max_age: config::HSTS_TWO_YEARS_SECS,
            hsts_include_subdomains: true,
            hsts_preload: false,
            rate_limiting_enabled: false,
            rate_limit: 60,
            rate_limit_burst: 10,
            trust_proxy_headers: false,
            max_connections: 1000,
            request_timeout: 30,
            max_request_size: 100 * 1024 * 1024,
            metrics_enabled: false,
            server_name: "Test".to_string(),
        }
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
        let config = test_middleware_config();
        let app = apply_middleware(test_router(), config, None, None);

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
            compression_enabled: true,
            compression_algorithms: vec![
                config::CompressionAlgorithm::Gzip,
                config::CompressionAlgorithm::Br,
            ],
            ..test_middleware_config()
        };

        let app = apply_middleware(test_router(), config, None, None);

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

    #[tokio::test]
    async fn test_apply_security_headers() {
        let config = MiddlewareConfig {
            hsts_enabled: true,
            hsts_max_age: 31536000, // 1 year (intentionally different from the 2-year default)
            ..test_middleware_config()
        };
        let app = apply_security_headers(test_router(), &config);

        let response = app
            .oneshot(Request::get("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let headers = response.headers();
        assert_eq!(
            headers.get("strict-transport-security").unwrap(),
            "max-age=31536000; includeSubDomains"
        );
        assert_eq!(
            headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert!(headers.get("content-security-policy").is_some());
        assert_eq!(
            headers.get("referrer-policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
        assert_eq!(headers.get("permissions-policy").unwrap(), "camera=(), microphone=(), geolocation=()");
        assert_eq!(headers.get("x-xss-protection").unwrap(), "0");
    }

    #[tokio::test]
    async fn test_security_headers_hsts_disabled() {
        let config = test_middleware_config(); // hsts_enabled defaults to false
        let app = apply_security_headers(test_router(), &config);

        let response = app
            .oneshot(Request::get("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // HSTS should not be present when disabled
        assert!(response.headers().get("strict-transport-security").is_none());
        // Other security headers still present
        assert!(response.headers().get("x-content-type-options").is_some());
    }

    #[tokio::test]
    async fn test_security_headers_hsts_preload() {
        let config = MiddlewareConfig {
            hsts_enabled: true,
            hsts_preload: true,
            ..test_middleware_config()
        };
        let app = apply_security_headers(test_router(), &config);

        let response = app
            .oneshot(Request::get("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let hsts = response
            .headers()
            .get("strict-transport-security")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(hsts.contains("preload"));
        assert!(hsts.contains("includeSubDomains"));
    }
}
