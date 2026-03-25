use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::info;

use crate::errors::AuthError;

/// Represents an authenticated user
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Username
    pub username: String,
    /// User groups/roles
    pub groups: Vec<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl User {
    pub fn new(username: String) -> Self {
        Self {
            username,
            groups: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.groups = groups;
        self
    }

    pub fn with_metadata(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Check if user is in a specific group
    pub fn is_in_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }

    /// Check if user matches any of the specified users/groups
    /// Supports '@' and '+' prefixes for group references, and also matches direct group names
    pub fn matches_any(&self, users_or_groups: &[String]) -> bool {
        if users_or_groups.is_empty() {
            return false; // Empty list means no specific access granted
        }

        for item in users_or_groups {
            // Check for group reference with @ or + prefix
            if let Some(group_name) = item.strip_prefix('@').or_else(|| item.strip_prefix('+')) {
                if self.is_in_group(group_name) {
                    return true;
                }
            } else if item == &self.username {
                // Direct username match
                return true;
            } else if self.is_in_group(item) {
                // Also check if the item matches a group name directly (without prefix)
                return true;
            }
        }

        false
    }
}

/// User database entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserEntry {
    /// Argon2id password hash
    password_hash: String,
    /// User groups
    #[serde(default)]
    groups: Vec<String>,
    /// User metadata
    #[serde(default)]
    metadata: HashMap<String, String>,
}

/// User store for authentication
#[derive(Debug, Clone)]
pub struct UserStore {
    users: HashMap<String, UserEntry>,
}

impl UserStore {
    /// Create a new empty user store
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    /// Load user store from a TOML file
    /// Format:
    /// ```toml
    /// [users.alice]
    /// password_hash = "$argon2id$..." # argon2id hash
    /// groups = ["admin", "users"]
    ///
    /// [users.bob]
    /// password_hash = "$argon2id$..."
    /// groups = ["users"]
    /// ```
    pub fn from_file(path: &Path) -> Result<Self, AuthError> {
        // Check if file exists first for better error messages
        if !path.exists() {
            return Err(AuthError::UserDbNotFound(path.to_path_buf()));
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| AuthError::UserDbParseError(format!("Failed to read file: {}", e)))?;

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct UserDb {
            users: HashMap<String, UserEntry>,
        }

        let db: UserDb = toml::from_str(&content)
            .map_err(|e| AuthError::UserDbParseError(format!("TOML parse error: {}", e)))?;

        if db.users.is_empty() {
            return Err(AuthError::EmptyUserDatabase);
        }

        Ok(Self { users: db.users })
    }

    /// Add a user to the store
    #[allow(dead_code)]
    pub fn add_user(
        &mut self,
        username: String,
        password_hash: String,
        groups: Vec<String>,
        metadata: HashMap<String, String>,
    ) {
        self.users.insert(
            username,
            UserEntry {
                password_hash,
                groups,
                metadata,
            },
        );
    }

    /// Verify a user's password and return a User object if valid
    ///
    /// Always performs an Argon2 hash computation, even when the username does not exist,
    /// to prevent timing-based username enumeration attacks.
    pub fn verify(&self, username: &str, password: &str) -> Option<User> {
        // Precomputed Argon2id hash with parameters matching server config (m=65536, t=3, p=4).
        // Used for a dummy verification when the username is not found, so that both the
        // "user not found" and "wrong password" paths take the same amount of time.
        const DUMMY_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        match self.users.get(username) {
            Some(entry) => {
                // Verify password using the shared stratus-auth library
                if stratus_auth::verify_password(password, &entry.password_hash)
                    .unwrap_or(false)
                {
                    Some(
                        User::new(username.to_string())
                            .with_groups(entry.groups.clone())
                            .with_metadata(entry.metadata.clone()),
                    )
                } else {
                    None
                }
            }
            None => {
                // Perform dummy verification to equalize timing with the found-but-wrong-password path
                let _ = stratus_auth::verify_password(password, DUMMY_HASH);
                None
            }
        }
    }

    /// Look up a user by username without password verification (for mTLS auth)
    pub fn get_user(&self, username: &str) -> Option<User> {
        self.users.get(username).map(|entry| {
            User::new(username.to_string())
                .with_groups(entry.groups.clone())
                .with_metadata(entry.metadata.clone())
        })
    }

    /// Check if a user exists in the store
    #[allow(dead_code)]
    pub fn contains_user(&self, username: &str) -> bool {
        self.users.contains_key(username)
    }

    /// Get the number of users in the store
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
}

impl Default for UserStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe user store wrapper that supports hot-reloading
#[derive(Debug, Clone)]
pub struct ReloadableUserStore {
    inner: Arc<RwLock<UserStore>>,
}

impl ReloadableUserStore {
    /// Create a new reloadable user store from an existing UserStore
    pub fn new(user_store: UserStore) -> Self {
        Self {
            inner: Arc::new(RwLock::new(user_store)),
        }
    }

    /// Load user store from a TOML file
    pub fn from_file(path: &Path) -> Result<Self, AuthError> {
        let user_store = UserStore::from_file(path)?;
        Ok(Self::new(user_store))
    }

    /// Reload the user store from a file
    pub fn reload(&self, path: &Path) -> Result<(), AuthError> {
        let new_store = UserStore::from_file(path)?;

        // Acquire write lock and replace the store
        let mut store = self.inner.write().unwrap();
        *store = new_store;

        info!("User database reloaded: {} user(s)", store.len());
        Ok(())
    }

    /// Verify a user's password and return a User object if valid
    pub fn verify(&self, username: &str, password: &str) -> Option<User> {
        let store = self.inner.read().unwrap();
        store.verify(username, password)
    }

    /// Look up a user by username without password verification (for mTLS auth)
    pub fn get_user(&self, username: &str) -> Option<User> {
        self.inner.read().unwrap().get_user(username)
    }

    /// Get the number of users in the store
    pub fn len(&self) -> usize {
        let store = self.inner.read().unwrap();
        store.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        let store = self.inner.read().unwrap();
        store.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_group_matching() {
        let user = User::new("alice".to_string()).with_groups(vec!["admin".to_string()]);

        assert!(user.is_in_group("admin"));
        assert!(!user.is_in_group("users"));

        // Test matches_any with groups using @ prefix
        assert!(user.matches_any(&["@admin".to_string()]));
        // Test matches_any with groups using + prefix
        assert!(user.matches_any(&["+admin".to_string()]));
        // Test matches_any with direct group name
        assert!(user.matches_any(&["admin".to_string()]));
        // Test matches_any with username
        assert!(user.matches_any(&["alice".to_string()]));
        // Test matches_any with mixed list
        assert!(user.matches_any(&["bob".to_string(), "@admin".to_string()]));
        assert!(!user.matches_any(&["bob".to_string(), "@users".to_string()]));

        // Empty list should not grant access (use separate authz logic for default access)
        assert!(!user.matches_any(&[]));
    }

    #[test]
    fn test_user_store() {
        let mut store = UserStore::new();

        // Generate an argon2id hash for testing using shared library
        let password_hash = stratus_auth::hash_password("password123").unwrap();

        store.add_user(
            "alice".to_string(),
            password_hash,
            vec!["admin".to_string()],
            HashMap::new(),
        );

        // Valid credentials
        let user = store.verify("alice", "password123");
        assert!(user.is_some());
        assert_eq!(user.as_ref().unwrap().username, "alice");
        assert!(user.as_ref().unwrap().is_in_group("admin"));

        // Invalid password
        assert!(store.verify("alice", "wrongpassword").is_none());

        // Non-existent user
        assert!(store.verify("bob", "password123").is_none());
    }

    #[test]
    fn test_user_store_file_not_found() {
        use std::path::PathBuf;

        let result = UserStore::from_file(&PathBuf::from("/nonexistent/path/users.toml"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AuthError::UserDbNotFound(_)));
    }

    #[test]
    fn test_user_store_invalid_toml() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "this is not valid TOML {{{{ ]]]]").unwrap();

        let result = UserStore::from_file(temp_file.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AuthError::UserDbParseError(_)));
    }

    #[test]
    fn test_user_store_empty_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "[users]").unwrap();

        let result = UserStore::from_file(temp_file.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AuthError::EmptyUserDatabase));
    }
}
