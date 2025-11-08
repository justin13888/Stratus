//! TLS configuration and setup
//!
//! This module handles TLS/SSL certificate configuration,
//! separating TLS concerns from main application logic.

use crate::config::TlsConfig;
use axum_server::tls_rustls::RustlsConfig;
use eyre::{Result, eyre};
use std::path::Path;

/// Configure Rustls from TLS configuration
///
/// Loads TLS certificates and private key from files specified in the configuration.
///
/// # Arguments
///
/// * `config` - TLS configuration containing certificate and key file paths
///
/// # Returns
///
/// Returns configured `RustlsConfig` on success, or an error if certificate loading fails
///
/// # Errors
///
/// Returns an error if:
/// - Certificate file cannot be read
/// - Key file cannot be read
/// - Certificate or key format is invalid
pub async fn configure_rustls(config: &TlsConfig) -> Result<RustlsConfig> {
    validate_tls_files(&config.cert_file, &config.key_file)?;

    RustlsConfig::from_pem_file(&config.cert_file, &config.key_file)
        .await
        .map_err(|e| eyre!("Failed to load TLS certificates: {}", e))
}

/// Validate that TLS certificate and key files exist
fn validate_tls_files(cert_file: &Path, key_file: &Path) -> Result<()> {
    if !cert_file.exists() {
        return Err(eyre!("TLS certificate file not found: {:?}", cert_file));
    }

    if !key_file.exists() {
        return Err(eyre!("TLS key file not found: {:?}", key_file));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_validate_tls_files_missing_cert() {
        let cert = PathBuf::from("/nonexistent/cert.pem");
        let key = PathBuf::from("/nonexistent/key.pem");

        let result = validate_tls_files(&cert, &key);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("certificate file not found")
        );
    }

    #[test]
    fn test_validate_tls_files_missing_key() {
        // Create a temporary cert file
        let temp_dir = tempfile::tempdir().unwrap();
        let cert = temp_dir.path().join("cert.pem");
        std::fs::write(&cert, "fake cert").unwrap();

        let key = PathBuf::from("/nonexistent/key.pem");

        let result = validate_tls_files(&cert, &key);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("key file not found")
        );
    }

    #[test]
    fn test_validate_tls_files_both_exist() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cert = temp_dir.path().join("cert.pem");
        let key = temp_dir.path().join("key.pem");

        std::fs::write(&cert, "fake cert").unwrap();
        std::fs::write(&key, "fake key").unwrap();

        let result = validate_tls_files(&cert, &key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_tls_files_with_valid_paths() {
        // Test with actual project cert files if they exist
        let cert = PathBuf::from("cert.pem");
        let key = PathBuf::from("key.pem");

        if cert.exists() && key.exists() {
            let result = validate_tls_files(&cert, &key);
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_configure_rustls_with_invalid_files() {
        let config = crate::config::TlsConfig {
            cert_file: PathBuf::from("/nonexistent/cert.pem"),
            key_file: PathBuf::from("/nonexistent/key.pem"),
            min_version: crate::config::TlsVersion::V1_3,
            ocsp_stapling: true,
            client_cert_mode: crate::config::ClientCertMode::None,
            client_ca_file: None,
        };

        let result = configure_rustls(&config).await;
        assert!(result.is_err());
    }

    // Note: Testing actual TLS configuration requires valid cert/key files
    // which are environment-specific. The validation logic is tested above.
}
