use crate::auth::provider::{AuthProvider, AuthResult};
use crate::auth::user::ReloadableUserStore;
use crate::errors::AuthError;
use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::debug;

/// HTTP Basic Authentication provider
pub struct BasicAuthProvider {
    user_store: Arc<ReloadableUserStore>,
    realm: String,
}

impl BasicAuthProvider {
    /// Create a new Basic Auth provider with the given user store
    pub fn new(user_store: ReloadableUserStore) -> Self {
        Self {
            user_store: Arc::new(user_store),
            realm: "Stratus".to_string(),
        }
    }

    /// Create a new Basic Auth provider with a custom realm
    pub fn with_realm(mut self, realm: String) -> Self {
        self.realm = realm;
        self
    }

    /// Get a reference to the user store (for file watching)
    pub fn user_store(&self) -> Arc<ReloadableUserStore> {
        Arc::clone(&self.user_store)
    }

    /// Parse the Authorization header and extract username and password
    fn parse_credentials(auth_header: &HeaderValue) -> Result<(String, String), AuthError> {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| AuthError::InvalidHeaderFormat)?;

        // Check if it starts with "Basic "
        if !auth_str.starts_with("Basic ") {
            return Err(AuthError::InvalidHeaderFormat);
        }

        // Extract the base64 encoded credentials
        let encoded = auth_str
            .strip_prefix("Basic ")
            .ok_or(AuthError::InvalidHeaderFormat)?
            .trim();

        // Decode from base64
        let decoded = BASE64
            .decode(encoded)
            .map_err(|_| AuthError::InvalidBase64)?;
        let decoded_str = String::from_utf8(decoded).map_err(|_| AuthError::InvalidBase64)?;

        // Split on the first colon to get username and password
        let mut parts = decoded_str.splitn(2, ':');
        let username = parts
            .next()
            .ok_or(AuthError::InvalidHeaderFormat)?
            .to_string();
        let password = parts
            .next()
            .ok_or(AuthError::InvalidHeaderFormat)?
            .to_string();

        Ok((username, password))
    }
}

impl AuthProvider for BasicAuthProvider {
    fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Pin<Box<dyn Future<Output = AuthResult> + Send + '_>> {
        // Extract Authorization header
        let auth_header = match headers.get(axum::http::header::AUTHORIZATION) {
            Some(header) => header,
            None => {
                debug!("No Authorization header present");
                return Box::pin(async { AuthResult::NoCredentials });
            }
        };

        // Parse credentials
        let (username, password) = match Self::parse_credentials(auth_header) {
            Ok(creds) => creds,
            Err(AuthError::InvalidHeaderFormat) => {
                debug!("Invalid Authorization header format");
                return Box::pin(async {
                    AuthResult::Failed("Invalid Authorization header format".to_string())
                });
            }
            Err(AuthError::InvalidBase64) => {
                debug!("Invalid base64 encoding in Authorization header");
                return Box::pin(async {
                    AuthResult::Failed("Invalid base64 encoding".to_string())
                });
            }
            Err(e) => {
                debug!("Unexpected error parsing credentials: {}", e);
                let msg = e.to_string();
                return Box::pin(async move {
                    AuthResult::Failed(format!("Authentication error: {}", msg))
                });
            }
        };

        debug!("Attempting to authenticate user: {}", username);

        // Clone the user_store Arc for use in the async block
        let user_store = Arc::clone(&self.user_store);

        Box::pin(async move {
            // Verify credentials against user store
            match user_store.verify(&username, &password) {
                Some(user) => {
                    debug!("User {} authenticated successfully", username);
                    AuthResult::Success(user)
                }
                None => {
                    debug!("Authentication failed for user: {}", username);
                    AuthResult::Failed(format!(
                        "Invalid username or password for user: {}",
                        username
                    ))
                }
            }
        })
    }

    fn scheme_name(&self) -> &'static str {
        "Basic"
    }

    fn challenge(&self) -> String {
        format!("Basic realm=\"{}\"", self.realm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::user::{ReloadableUserStore, UserStore};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_basic_auth_success() {
        let mut store = UserStore::new();
        let password_hash = stratus_auth::hash_password("secret123").unwrap();
        store.add_user(
            "alice".to_string(),
            password_hash,
            vec!["users".to_string()],
            HashMap::new(),
        );

        let provider = BasicAuthProvider::new(ReloadableUserStore::new(store));

        // Create valid Basic Auth header
        let credentials = BASE64.encode("alice:secret123");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {}", credentials).parse().unwrap(),
        );

        let result = provider.authenticate(&headers).await;
        assert!(matches!(result, AuthResult::Success(_)));

        if let AuthResult::Success(user) = result {
            assert_eq!(user.username, "alice");
            assert!(user.is_in_group("users"));
        }
    }

    #[tokio::test]
    async fn test_basic_auth_invalid_password() {
        let mut store = UserStore::new();
        let password_hash = stratus_auth::hash_password("secret123").unwrap();
        store.add_user("alice".to_string(), password_hash, vec![], HashMap::new());

        let provider = BasicAuthProvider::new(ReloadableUserStore::new(store));

        // Create Basic Auth header with wrong password
        let credentials = BASE64.encode("alice:wrongpassword");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {}", credentials).parse().unwrap(),
        );

        let result = provider.authenticate(&headers).await;
        assert!(matches!(result, AuthResult::Failed(_)));
    }

    #[tokio::test]
    async fn test_basic_auth_no_credentials() {
        let store = UserStore::new();
        let provider = BasicAuthProvider::new(ReloadableUserStore::new(store));

        let headers = HeaderMap::new();
        let result = provider.authenticate(&headers).await;
        assert!(matches!(result, AuthResult::NoCredentials));
    }

    #[tokio::test]
    async fn test_basic_auth_malformed_header() {
        let store = UserStore::new();
        let provider = BasicAuthProvider::new(ReloadableUserStore::new(store));

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer token123".parse().unwrap(),
        );

        let result = provider.authenticate(&headers).await;
        assert!(matches!(result, AuthResult::Failed(_)));
    }

    #[test]
    fn test_parse_credentials() {
        // Valid credentials
        let credentials = BASE64.encode("alice:password123");
        let header = format!("Basic {}", credentials).parse().unwrap();
        let result = BasicAuthProvider::parse_credentials(&header);
        assert_eq!(result, Ok(("alice".to_string(), "password123".to_string())));

        // Credentials with colon in password
        let credentials = BASE64.encode("user:pass:word");
        let header = format!("Basic {}", credentials).parse().unwrap();
        let result = BasicAuthProvider::parse_credentials(&header);
        assert_eq!(result, Ok(("user".to_string(), "pass:word".to_string())));

        // Invalid scheme
        let header = "Bearer token123".parse().unwrap();
        let result = BasicAuthProvider::parse_credentials(&header);
        assert!(matches!(result, Err(AuthError::InvalidHeaderFormat)));
    }
}
