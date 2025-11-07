mod basic;
mod middleware;
mod provider;
mod user;
mod watcher;

pub use middleware::{AuthMiddleware, get_authenticated_user};
pub use provider::AuthProvider;
use tracing::{info, warn};
pub use user::User;

use crate::{
    auth::{basic::BasicAuthProvider, user::ReloadableUserStore},
    config::{AuthMethod, SecurityConfig},
};
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
            let user_store = ReloadableUserStore::from_file(user_db_path)?;

            // Warn if user store is empty (would lock everyone out)
            if user_store.is_empty() {
                warn!(
                    "User database {:?} is empty - no users will be able to authenticate!",
                    user_db_path
                );
            } else {
                info!(
                    "Loaded {} user(s) from {:?}",
                    user_store.len(),
                    user_db_path
                );
            }

            let provider = BasicAuthProvider::new(user_store);

            // Start file watcher for hot-reloading
            let user_store_arc = provider.user_store();
            let db_path = user_db_path.clone();

            if let Err(e) = watcher::start_user_db_watcher(user_store_arc, db_path) {
                warn!("Failed to start user database file watcher: {}", e);
                warn!("User database will not be hot-reloaded on changes");
            } else {
                info!("Hot-reloading enabled for user database");
            }

            Ok(Arc::new(provider))
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
