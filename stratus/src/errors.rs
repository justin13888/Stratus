//! Error types for the Stratus file server
//!
//! This module defines typed errors for different subsystems,
//! making error handling more explicit and testable.

use std::path::PathBuf;

use thiserror::Error;

/// Authentication-related errors
#[derive(Debug, PartialEq, Error)]
pub enum AuthError {
    #[error("Invalid authorization header format")]
    InvalidHeaderFormat,

    #[error("Invalid Base64 encoding in credentials")]
    InvalidBase64,

    #[error("User database file not found: {0}")]
    UserDbNotFound(PathBuf),

    #[error("Failed to parse user database: {0}")]
    UserDbParseError(String),

    #[error("User database is empty")]
    EmptyUserDatabase,
}

/// Share access and permission errors
#[derive(Debug, Error)]
pub enum ShareError {
    #[error("Share not found: {0}")]
    NotFound(String),

    #[error("Share is disabled: {0}")]
    Disabled(String),

    #[error("Access denied to share: {0}")]
    AccessDenied(String),

    #[error("Path not found: {0}")]
    PathNotFound(PathBuf),

    #[error("Path traversal attempt detected: {path:?} escapes {base:?}")]
    PathTraversal { path: PathBuf, base: PathBuf },

    #[allow(dead_code)]
    #[error("Symlink access denied: {0:?}")]
    SymlinkDenied(PathBuf),

    #[error("Failed to read directory: {0}")]
    DirectoryReadError(String),

    #[error("Failed to read file: {0}")]
    FileReadError(String),
}

/// Virtual filesystem errors
#[derive(Debug, Error)]
pub enum VfsError {
    #[error("Path not found: {0:?}")]
    NotFound(PathBuf),

    #[error("Permission denied: {0:?}")]
    PermissionDenied(PathBuf),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Configuration errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Configuration file not found: {0:?}")]
    FileNotFound(PathBuf),

    #[error("Failed to parse configuration: {0}")]
    ParseError(String),

    #[error("TLS certificate file not found: {0:?}")]
    CertNotFound(PathBuf),

    #[error("TLS key file not found: {0:?}")]
    KeyNotFound(PathBuf),

    #[error("Share path does not exist: {share} -> {path:?}")]
    SharePathNotFound { share: String, path: PathBuf },

    #[error("Share path is not a directory: {share} -> {path:?}")]
    SharePathNotDirectory { share: String, path: PathBuf },

    #[error("Invalid HTTP/2 configuration: {0}")]
    InvalidHttp2Config(String),

    #[error("Share '{share}' has unsupported option enabled: {reason}")]
    UnsupportedShareOption { share: String, reason: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_error_display() {
        let error = AuthError::InvalidHeaderFormat;
        assert_eq!(error.to_string(), "Invalid authorization header format");

        let error = AuthError::InvalidBase64;
        assert_eq!(error.to_string(), "Invalid Base64 encoding in credentials");
    }

    #[test]
    fn test_auth_error_with_path() {
        let path = PathBuf::from("/etc/users.toml");
        let error = AuthError::UserDbNotFound(path.clone());
        assert!(error.to_string().contains("/etc/users.toml"));
    }

    #[test]
    fn test_share_error_display() {
        let error = ShareError::NotFound("public".to_string());
        assert_eq!(error.to_string(), "Share not found: public");

        let error = ShareError::Disabled("admin".to_string());
        assert_eq!(error.to_string(), "Share is disabled: admin");

        let error = ShareError::AccessDenied("private".to_string());
        assert_eq!(error.to_string(), "Access denied to share: private");
    }

    #[test]
    fn test_share_error_path_traversal() {
        let path = PathBuf::from("/share/../etc/passwd");
        let base = PathBuf::from("/share");
        let error = ShareError::PathTraversal {
            path: path.clone(),
            base: base.clone(),
        };

        let msg = error.to_string();
        assert!(msg.contains("escapes"));
        assert!(msg.contains("/etc/passwd"));
    }

    #[test]
    fn test_vfs_error_display() {
        let path = PathBuf::from("/nonexistent");
        let error = VfsError::NotFound(path.clone());
        assert!(error.to_string().contains("/nonexistent"));

        let error = VfsError::PermissionDenied(path.clone());
        assert!(error.to_string().contains("Permission denied"));
    }

    #[test]
    fn test_vfs_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let vfs_err: VfsError = io_err.into();
        assert!(vfs_err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_config_error_display() {
        let path = PathBuf::from("config.toml");
        let error = ConfigError::FileNotFound(path.clone());
        assert!(error.to_string().contains("config.toml"));

        let error = ConfigError::ParseError("invalid TOML syntax".to_string());
        assert!(error.to_string().contains("invalid TOML syntax"));
    }

    #[test]
    fn test_config_error_share_validation() {
        let error = ConfigError::SharePathNotFound {
            share: "public".to_string(),
            path: PathBuf::from("/missing"),
        };

        let msg = error.to_string();
        assert!(msg.contains("public"));
        assert!(msg.contains("/missing"));
        assert!(msg.contains("does not exist"));
    }

    #[test]
    fn test_all_auth_errors() {
        // Ensure all variants can be constructed and displayed
        let errors = vec![
            AuthError::InvalidHeaderFormat,
            AuthError::InvalidBase64,
            AuthError::UserDbNotFound(PathBuf::from("/tmp/users.toml")),
            AuthError::UserDbParseError("test".to_string()),
            AuthError::EmptyUserDatabase,
        ];

        for error in errors {
            // Each error should have a non-empty string representation
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn test_error_is_send_sync() {
        // Verify errors can be sent across threads
        fn is_send<T: Send>() {}
        fn is_sync<T: Sync>() {}

        is_send::<AuthError>();
        is_sync::<AuthError>();
        is_send::<ShareError>();
        is_sync::<ShareError>();
        is_send::<VfsError>();
        is_sync::<VfsError>();
        is_send::<ConfigError>();
        is_sync::<ConfigError>();
    }
}
