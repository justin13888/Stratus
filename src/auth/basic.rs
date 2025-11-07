use crate::auth::provider::{AuthProvider, AuthResult};
use crate::auth::user::UserStore;
use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::debug;

/// HTTP Basic Authentication provider
pub struct BasicAuthProvider {
    user_store: Arc<UserStore>,
    realm: String,
}

impl BasicAuthProvider {
    /// Create a new Basic Auth provider with the given user store
    pub fn new(user_store: UserStore) -> Self {
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

    /// Parse the Authorization header and extract username and password
    fn parse_credentials(auth_header: &HeaderValue) -> Option<(String, String)> {
        let auth_str = auth_header.to_str().ok()?;

        // Check if it starts with "Basic "
        if !auth_str.starts_with("Basic ") {
            return None;
        }

        // Extract the base64 encoded credentials
        let encoded = auth_str.strip_prefix("Basic ")?.trim();

        // Decode from base64
        let decoded = BASE64.decode(encoded).ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;

        // Split on the first colon to get username and password
        let mut parts = decoded_str.splitn(2, ':');
        let username = parts.next()?.to_string();
        let password = parts.next()?.to_string();

        Some((username, password))
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
            Some(creds) => creds,
            None => {
                debug!("Failed to parse Basic Auth credentials");
                return Box::pin(async {
                    AuthResult::Failed("Invalid Authorization header format".to_string())
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
    use crate::auth::user::UserStore;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_basic_auth_success() {
        use argon2::password_hash::SaltString;
        use argon2::{Argon2, PasswordHasher};

        let mut store = UserStore::new();
        let salt = SaltString::encode_b64(&[0u8; 16]).unwrap();
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(b"secret123", &salt)
            .unwrap()
            .to_string();
        store.add_user(
            "alice".to_string(),
            password_hash,
            vec!["users".to_string()],
            HashMap::new(),
        );

        let provider = BasicAuthProvider::new(store);

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
        use argon2::password_hash::SaltString;
        use argon2::{Argon2, PasswordHasher};

        let mut store = UserStore::new();
        let salt = SaltString::encode_b64(&[0u8; 16]).unwrap();
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(b"secret123", &salt)
            .unwrap()
            .to_string();
        store.add_user("alice".to_string(), password_hash, vec![], HashMap::new());

        let provider = BasicAuthProvider::new(store);

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
        let provider = BasicAuthProvider::new(store);

        let headers = HeaderMap::new();
        let result = provider.authenticate(&headers).await;
        assert!(matches!(result, AuthResult::NoCredentials));
    }

    #[tokio::test]
    async fn test_basic_auth_malformed_header() {
        let store = UserStore::new();
        let provider = BasicAuthProvider::new(store);

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
        assert_eq!(
            result,
            Some(("alice".to_string(), "password123".to_string()))
        );

        // Credentials with colon in password
        let credentials = BASE64.encode("user:pass:word");
        let header = format!("Basic {}", credentials).parse().unwrap();
        let result = BasicAuthProvider::parse_credentials(&header);
        assert_eq!(result, Some(("user".to_string(), "pass:word".to_string())));

        // Invalid scheme
        let header = "Bearer token123".parse().unwrap();
        let result = BasicAuthProvider::parse_credentials(&header);
        assert_eq!(result, None);
    }
}
