use crate::auth::provider::{AuthProvider, AuthResult};
use crate::auth::rate_limit::AuthRateLimiter;
use crate::auth::user::User;
use axum::{
    body::Body,
    extract::{ConnectInfo, Request},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use tracing::{debug, warn};

/// Extension type to store authenticated user in request extensions
#[derive(Clone, Debug)]
pub struct AuthenticatedUser(pub User);

impl Deref for AuthenticatedUser {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Authentication middleware
#[derive(Clone)]
pub struct AuthMiddleware {
    provider: Arc<dyn AuthProvider + Send + Sync>,
    /// Optional per-IP brute-force protection. `None` disables lockout enforcement.
    rate_limiter: Option<Arc<AuthRateLimiter>>,
}

impl AuthMiddleware {
    /// Create a new authentication middleware with the given provider
    pub fn new(provider: Arc<dyn AuthProvider + Send + Sync>) -> Self {
        Self {
            provider,
            rate_limiter: None,
        }
    }

    /// Attach a rate limiter for brute-force protection
    pub fn with_rate_limiter(mut self, limiter: Arc<AuthRateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Extract the client IP from the request (from ConnectInfo extension)
    fn client_ip(request: &Request) -> Option<std::net::IpAddr> {
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
    }

    /// Build a 401 response with the auth challenge header
    fn unauthorized_response(challenge: &str) -> Response {
        let mut response = Response::new(Body::from("Authentication required"));
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        if !challenge.is_empty()
            && let Ok(header_value) = HeaderValue::from_str(challenge)
        {
            response
                .headers_mut()
                .insert(axum::http::header::WWW_AUTHENTICATE, header_value);
        }
        response
    }

    /// Build a 429 response indicating the client IP is locked out
    fn locked_out_response(remaining_secs: u64) -> Response {
        let mut response = Response::new(Body::from("Too many failed attempts"));
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        if let Ok(retry_after) = HeaderValue::from_str(&remaining_secs.to_string()) {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, retry_after);
        }
        response
    }

    /// Middleware function to authenticate requests
    ///
    /// Takes `self` by value to avoid lifetime issues in async closures.
    /// This is cheap since `AuthMiddleware` only contains `Arc`s.
    pub async fn authenticate(self, mut request: Request, next: Next) -> Response {
        let client_ip = Self::client_ip(&request);

        // Check for active auth lockout before attempting authentication
        if let (Some(limiter), Some(ip)) = (&self.rate_limiter, client_ip) {
            if let Some(remaining) = limiter.check_locked(ip) {
                warn!(ip = %ip, remaining_secs = remaining.as_secs(), "Auth request blocked: IP is locked out");
                return Self::locked_out_response(remaining.as_secs());
            }
        }

        let auth_result = self.provider.authenticate(&request).await;

        match auth_result {
            AuthResult::Success(user) => {
                debug!("Request authenticated as user: {}", user.username);
                // Successful auth resets the failure counter
                if let (Some(limiter), Some(ip)) = (&self.rate_limiter, client_ip) {
                    limiter.record_success(ip);
                }
                // Store the authenticated user in request extensions
                request.extensions_mut().insert(AuthenticatedUser(user));
                // Continue to next middleware/handler
                next.run(request).await
            }
            AuthResult::NoCredentials => {
                warn!("Request rejected: no credentials provided");
                Self::unauthorized_response(&self.provider.challenge())
            }
            AuthResult::Failed(reason) => {
                warn!("Request rejected: authentication failed - {}", reason);
                // Record failure for brute-force protection
                if let (Some(limiter), Some(ip)) = (&self.rate_limiter, client_ip) {
                    limiter.record_failure(ip);
                }
                // Note: keep the detailed reason in logs only, not in the response body
                Self::unauthorized_response(&self.provider.challenge())
            }
        }
    }
}

/// Helper function to extract authenticated user from request extensions
pub fn get_authenticated_user(request: &Request) -> Option<&User> {
    request
        .extensions()
        .get::<AuthenticatedUser>()
        .map(|au| &**au)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::basic::BasicAuthProvider;
    use crate::auth::user::{ReloadableUserStore, UserStore};
    use axum::{
        Router, body::Body, http::StatusCode, middleware, response::IntoResponse, routing::get,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use std::collections::HashMap;
    use tower::ServiceExt;

    async fn test_handler(request: Request) -> impl IntoResponse {
        if let Some(user) = get_authenticated_user(&request) {
            (StatusCode::OK, format!("Hello, {}", user.username))
        } else {
            (StatusCode::UNAUTHORIZED, "Not authenticated".to_string())
        }
    }

    #[tokio::test]
    async fn test_auth_middleware_success() {
        let mut store = UserStore::new();
        let password_hash = stratus_auth::hash_password("secret").unwrap();
        store.add_user("alice".to_string(), password_hash, vec![], HashMap::new());

        let provider: Arc<dyn AuthProvider + Send + Sync> =
            Arc::new(BasicAuthProvider::new(ReloadableUserStore::new(store)));
        let auth_middleware = AuthMiddleware::new(provider);

        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn(move |req, next| {
                auth_middleware.clone().authenticate(req, next)
            }));

        // Test with valid credentials
        let credentials = BASE64.encode("alice:secret");
        let request = axum::http::Request::builder()
            .uri("/test")
            .header("Authorization", format!("Basic {}", credentials))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_middleware_no_credentials() {
        let store = UserStore::new();
        let provider: Arc<dyn AuthProvider + Send + Sync> =
            Arc::new(BasicAuthProvider::new(ReloadableUserStore::new(store)));
        let auth_middleware = AuthMiddleware::new(provider);

        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn(move |req, next| {
                auth_middleware.clone().authenticate(req, next)
            }));

        // Test without credentials
        let request = axum::http::Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            response
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_auth_middleware_invalid_credentials() {
        let mut store = UserStore::new();
        let password_hash = stratus_auth::hash_password("secret").unwrap();
        store.add_user("alice".to_string(), password_hash, vec![], HashMap::new());

        let provider: Arc<dyn AuthProvider + Send + Sync> =
            Arc::new(BasicAuthProvider::new(ReloadableUserStore::new(store)));
        let auth_middleware = AuthMiddleware::new(provider);

        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn(move |req, next| {
                auth_middleware.clone().authenticate(req, next)
            }));

        // Test with invalid credentials
        let credentials = BASE64.encode("alice:wrongpassword");
        let request = axum::http::Request::builder()
            .uri("/test")
            .header("Authorization", format!("Basic {}", credentials))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
