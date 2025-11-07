mod basic;
mod middleware;
mod provider;
mod user;

pub use middleware::{AuthMiddleware, get_authenticated_user};
pub use provider::AuthProvider;
pub use user::{User, UserStore};

use crate::config::{AuthMethod, SecurityConfig};
use eyre::Result;
use std::sync::Arc;

/// Creates an appropriate auth provider based on the security configuration
pub fn create_auth_provider(
    security_config: &SecurityConfig,
) -> Result<Arc<dyn AuthProvider + Send + Sync>> {
    if !security_config.auth_required {
        return Ok(Arc::new(provider::NoAuth));
    }

    match security_config.auth_method {
        AuthMethod::Basic => {
            // Basic auth REQUIRES a user database file
            let user_db_path = security_config.user_db_file.as_ref().ok_or_else(|| {
                eyre::eyre!(
                    "Basic authentication enabled but 'user_db_file' not specified in config. \
                     Please set [security] user_db_file = \"users.toml\" or disable authentication."
                )
            })?;

            // Load and validate user database at startup (fail fast)
            let user_store = UserStore::from_file(user_db_path)?;

            // Warn if user store is empty (would lock everyone out)
            if user_store.is_empty() {
                tracing::warn!(
                    "User database {:?} is empty - no users will be able to authenticate!",
                    user_db_path
                );
            } else {
                tracing::info!(
                    "Loaded {} user(s) from {:?}",
                    user_store.len(),
                    user_db_path
                );
            }

            Ok(Arc::new(basic::BasicAuthProvider::new(user_store)))
        }
        AuthMethod::Bearer => {
            // Placeholder for future JWT/Bearer implementation
            // TODO
            eyre::bail!("Bearer token authentication not yet implemented")
        }
        AuthMethod::MutualTls => {
            // Placeholder for future mTLS implementation
            // TODO
            eyre::bail!("Mutual TLS authentication not yet implemented")
        }
    }
}
