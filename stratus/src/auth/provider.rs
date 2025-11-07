use crate::auth::user::User;
use axum::http::HeaderMap;
use std::future::Future;
use std::pin::Pin;

/// Result of an authentication attempt
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication successful with user information
    Success(User),
    /// Authentication failed with a reason
    Failed(String),
    /// No credentials provided
    NoCredentials,
}

/// Trait for authentication providers
///
/// This abstraction allows different authentication methods to be implemented
/// (Basic Auth, Bearer tokens, mTLS, etc.) while providing a common interface
pub trait AuthProvider {
    /// Authenticate a request based on headers
    fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Pin<Box<dyn Future<Output = AuthResult> + Send + '_>>;

    /// Get the authentication scheme name (e.g., "Basic", "Bearer")
    fn scheme_name(&self) -> &'static str;

    /// Get the WWW-Authenticate challenge header value
    fn challenge(&self) -> String {
        format!("{} realm=\"Stratus\"", self.scheme_name())
    }
}

/// No-op authentication provider that allows all requests
pub struct NoAuth;

impl AuthProvider for NoAuth {
    fn authenticate(
        &self,
        _headers: &HeaderMap,
    ) -> Pin<Box<dyn Future<Output = AuthResult> + Send + '_>> {
        Box::pin(async { AuthResult::Success(User::new("anonymous".to_string())) })
    }

    fn scheme_name(&self) -> &'static str {
        "None"
    }

    fn challenge(&self) -> String {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_no_auth() {
        let provider = NoAuth;
        let headers = HeaderMap::new();

        let result = provider.authenticate(&headers).await;
        assert!(matches!(result, AuthResult::Success(_)));

        if let AuthResult::Success(user) = result {
            assert_eq!(user.username, "anonymous");
        }
    }
}
