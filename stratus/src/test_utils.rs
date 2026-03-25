//! Test utilities and builders
//!
//! This module provides builder patterns and helper functions
//! for creating test fixtures, making tests more readable and maintainable.

use crate::auth::User;
use crate::config::{AuthMethod, MtlsUserMapping, NetworkConfig, SecurityConfig, ShareConfig};
use std::collections::HashMap;
use std::path::PathBuf;

/// Builder for creating `User` instances in tests
pub struct UserBuilder {
    username: String,
    groups: Vec<String>,
    metadata: HashMap<String, String>,
}

impl UserBuilder {
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            groups: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.groups.push(group.into());
        self
    }

    pub fn with_groups(mut self, groups: Vec<impl Into<String>>) -> Self {
        self.groups = groups.into_iter().map(|g| g.into()).collect();
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> User {
        User {
            username: self.username,
            groups: self.groups,
            metadata: self.metadata,
        }
    }
}

/// Builder for creating `ShareConfig` instances in tests
pub struct ShareConfigBuilder {
    path: PathBuf,
    enabled: bool,
    browseable: bool,
    read_only: bool,
    read_list: Vec<String>,
    write_list: Vec<String>,
    admin_list: Vec<String>,
    deny_list: Vec<String>,
    guest_ok: bool,
    hide_dot_files: bool,
    follow_symlinks: bool,
    exclude_patterns: Vec<String>,
    include_patterns: Vec<String>,
}

impl ShareConfigBuilder {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            enabled: true,
            browseable: true,
            read_only: false,
            read_list: Vec::new(),
            write_list: Vec::new(),
            admin_list: Vec::new(),
            deny_list: Vec::new(),
            guest_ok: false,
            hide_dot_files: false,
            follow_symlinks: false,
            exclude_patterns: Vec::new(),
            include_patterns: Vec::new(),
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn browseable(mut self, browseable: bool) -> Self {
        self.browseable = browseable;
        self
    }

    pub fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    pub fn guest_ok(mut self, guest_ok: bool) -> Self {
        self.guest_ok = guest_ok;
        self
    }

    pub fn with_read_access(mut self, users: Vec<impl Into<String>>) -> Self {
        self.read_list = users.into_iter().map(|u| u.into()).collect();
        self
    }

    pub fn with_write_access(mut self, users: Vec<impl Into<String>>) -> Self {
        self.write_list = users.into_iter().map(|u| u.into()).collect();
        self
    }

    pub fn with_admin_access(mut self, users: Vec<impl Into<String>>) -> Self {
        self.admin_list = users.into_iter().map(|u| u.into()).collect();
        self
    }

    pub fn with_deny_list(mut self, users: Vec<impl Into<String>>) -> Self {
        self.deny_list = users.into_iter().map(|u| u.into()).collect();
        self
    }

    pub fn hide_dot_files(mut self, hide: bool) -> Self {
        self.hide_dot_files = hide;
        self
    }

    pub fn follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }

    pub fn with_exclude_patterns(mut self, patterns: Vec<impl Into<String>>) -> Self {
        self.exclude_patterns = patterns.into_iter().map(|p| p.into()).collect();
        self
    }

    pub fn with_include_patterns(mut self, patterns: Vec<impl Into<String>>) -> Self {
        self.include_patterns = patterns.into_iter().map(|p| p.into()).collect();
        self
    }

    pub fn build(self) -> ShareConfig {
        ShareConfig {
            description: None,
            path: self.path,
            enabled: self.enabled,
            browseable: self.browseable,
            read_only: self.read_only,
            read_list: self.read_list,
            write_list: self.write_list,
            admin_list: self.admin_list,
            deny_list: self.deny_list,
            guest_ok: self.guest_ok,
            max_connections: None,
            hide_dot_files: self.hide_dot_files,
            follow_symlinks: self.follow_symlinks,
            exclude_patterns: self.exclude_patterns,
            include_patterns: self.include_patterns,
            versioning: false,
            max_file_size: 0,
            file_locking: true,
            mount_point: None,
        }
    }
}

/// Builder for creating `SecurityConfig` instances in tests
pub struct SecurityConfigBuilder {
    auth_required: bool,
    auth_method: AuthMethod,
    user_db_file: Option<PathBuf>,
    cors_enabled: bool,
    cors_allowed_origins: Vec<String>,
}

impl SecurityConfigBuilder {
    pub fn new() -> Self {
        Self {
            auth_required: true,
            auth_method: AuthMethod::Basic,
            user_db_file: None,
            cors_enabled: false,
            cors_allowed_origins: Vec::new(),
        }
    }

    pub fn auth_required(mut self, required: bool) -> Self {
        self.auth_required = required;
        self
    }

    pub fn auth_method(mut self, method: AuthMethod) -> Self {
        self.auth_method = method;
        self
    }

    pub fn user_db_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.user_db_file = Some(path.into());
        self
    }

    pub fn cors_enabled(mut self, enabled: bool) -> Self {
        self.cors_enabled = enabled;
        self
    }

    pub fn build(self) -> SecurityConfig {
        SecurityConfig {
            auth_required: self.auth_required,
            auth_method: self.auth_method,
            user_db_file: self.user_db_file,
            cors_enabled: self.cors_enabled,
            cors_allowed_origins: self.cors_allowed_origins,
            hsts_enabled: true,
            hsts_max_age: 63072000,
            hsts_include_subdomains: true,
            hsts_preload: false,
            rate_limiting_enabled: false,
            rate_limit: 60,
            rate_limit_burst: 10,
            trust_proxy_headers: false,
            auth_lockout_threshold: 5,
            auth_lockout_duration: 30,
            auth_lockout_multiplier: 2.0,
            auth_lockout_max_duration: 1800,
            mtls_user_mapping: MtlsUserMapping::Cn,
            compression_enabled: true,
            compression_algorithms: vec![],
            compression_min_size: 1024,
        }
    }
}

/// Builder for creating `NetworkConfig` instances in tests
pub struct NetworkConfigBuilder {
    max_connections: usize,
    tcp_nodelay: bool,
    tcp_keepalive: bool,
    tcp_keepalive_interval: u64,
}

impl NetworkConfigBuilder {
    pub fn new() -> Self {
        Self {
            max_connections: 1000,
            tcp_nodelay: true,
            tcp_keepalive: true,
            tcp_keepalive_interval: 60,
        }
    }

    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    pub fn tcp_nodelay(mut self, enabled: bool) -> Self {
        self.tcp_nodelay = enabled;
        self
    }

    pub fn tcp_keepalive(mut self, enabled: bool) -> Self {
        self.tcp_keepalive = enabled;
        self
    }

    pub fn build(self) -> NetworkConfig {
        NetworkConfig {
            max_connections: self.max_connections,
            connection_timeout: 60,
            request_timeout: 30,
            max_request_size: 100,
            tcp_keepalive: self.tcp_keepalive,
            tcp_keepalive_interval: self.tcp_keepalive_interval,
            tcp_nodelay: self.tcp_nodelay,
            listen_backlog: 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_builder_basic() {
        let user = UserBuilder::new("alice").build();

        assert_eq!(user.username, "alice");
        assert!(user.groups.is_empty());
        assert!(user.metadata.is_empty());
    }

    #[test]
    fn test_user_builder_with_groups() {
        let user = UserBuilder::new("bob")
            .with_group("admin")
            .with_group("users")
            .build();

        assert_eq!(user.username, "bob");
        assert_eq!(user.groups, vec!["admin", "users"]);
    }

    #[test]
    fn test_user_builder_with_groups_vec() {
        let user = UserBuilder::new("charlie")
            .with_groups(vec!["developers", "testers"])
            .build();

        assert_eq!(user.groups, vec!["developers", "testers"]);
    }

    #[test]
    fn test_user_builder_with_metadata() {
        let user = UserBuilder::new("dave")
            .with_metadata("email", "dave@example.com")
            .with_metadata("dept", "engineering")
            .build();

        assert_eq!(
            user.metadata.get("email"),
            Some(&"dave@example.com".to_string())
        );
        assert_eq!(user.metadata.get("dept"), Some(&"engineering".to_string()));
    }

    #[test]
    fn test_share_config_builder_defaults() {
        let config = ShareConfigBuilder::new("/tmp/share").build();

        assert_eq!(config.path, PathBuf::from("/tmp/share"));
        assert!(config.enabled);
        assert!(config.browseable);
        assert!(!config.read_only);
        assert!(!config.guest_ok);
    }

    #[test]
    fn test_share_config_builder_read_only() {
        let config = ShareConfigBuilder::new("/tmp/share")
            .read_only(true)
            .build();

        assert!(config.read_only);
    }

    #[test]
    fn test_share_config_builder_guest_access() {
        let config = ShareConfigBuilder::new("/tmp/share").guest_ok(true).build();

        assert!(config.guest_ok);
    }

    #[test]
    fn test_share_config_builder_access_lists() {
        let config = ShareConfigBuilder::new("/tmp/share")
            .with_read_access(vec!["alice", "bob"])
            .with_write_access(vec!["charlie"])
            .with_admin_access(vec!["admin"])
            .with_deny_list(vec!["hacker"])
            .build();

        assert_eq!(config.read_list, vec!["alice", "bob"]);
        assert_eq!(config.write_list, vec!["charlie"]);
        assert_eq!(config.admin_list, vec!["admin"]);
        assert_eq!(config.deny_list, vec!["hacker"]);
    }

    #[test]
    fn test_share_config_builder_patterns() {
        let config = ShareConfigBuilder::new("/tmp/share")
            .with_exclude_patterns(vec!["*.tmp", "*.log"])
            .with_include_patterns(vec!["*.txt", "*.md"])
            .build();

        assert_eq!(config.exclude_patterns, vec!["*.tmp", "*.log"]);
        assert_eq!(config.include_patterns, vec!["*.txt", "*.md"]);
    }

    #[test]
    fn test_share_config_builder_symlinks_and_dots() {
        let config = ShareConfigBuilder::new("/tmp/share")
            .follow_symlinks(true)
            .hide_dot_files(true)
            .build();

        assert!(config.follow_symlinks);
        assert!(config.hide_dot_files);
    }

    #[test]
    fn test_security_config_builder_defaults() {
        let config = SecurityConfigBuilder::new().build();

        assert!(config.auth_required);
        assert!(matches!(config.auth_method, AuthMethod::Basic));
        assert!(!config.cors_enabled);
    }

    #[test]
    fn test_security_config_builder_custom() {
        let config = SecurityConfigBuilder::new()
            .auth_required(false)
            .cors_enabled(true)
            .build();

        assert!(!config.auth_required);
        assert!(config.cors_enabled);
    }

    #[test]
    fn test_network_config_builder_defaults() {
        let config = NetworkConfigBuilder::new().build();

        assert_eq!(config.max_connections, 1000);
        assert!(config.tcp_nodelay);
        assert!(config.tcp_keepalive);
    }

    #[test]
    fn test_network_config_builder_custom() {
        let config = NetworkConfigBuilder::new()
            .max_connections(5000)
            .tcp_nodelay(false)
            .build();

        assert_eq!(config.max_connections, 5000);
        assert!(!config.tcp_nodelay);
    }

    #[test]
    fn test_builder_chaining() {
        // Test that builders can be chained fluently
        let user = UserBuilder::new("test")
            .with_group("group1")
            .with_group("group2")
            .with_metadata("key", "value")
            .build();

        assert_eq!(user.groups.len(), 2);
        assert_eq!(user.metadata.len(), 1);
    }

    #[test]
    fn test_realistic_scenario() {
        // Test a realistic scenario with multiple builders
        let admin_user = UserBuilder::new("admin")
            .with_groups(vec!["admins", "users"])
            .build();

        let share = ShareConfigBuilder::new("/var/www")
            .browseable(true)
            .with_admin_access(vec!["@admins"])
            .with_write_access(vec!["@developers"])
            .with_read_access(vec!["@users"])
            .hide_dot_files(true)
            .build();

        assert_eq!(admin_user.groups, vec!["admins", "users"]);
        assert_eq!(share.admin_list, vec!["@admins"]);
    }
}
