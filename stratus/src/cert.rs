//! TLS certificate generation utilities.
//!
//! Provides self-signed certificate generation for development and initial setup
//! using the `rcgen` crate.

use eyre::{Result, eyre};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use std::net::IpAddr;
use std::path::Path;
use tracing::warn;

/// Generate a self-signed TLS certificate and private key, writing both to files.
///
/// # Arguments
///
/// * `cn` - Common Name (e.g. "localhost" or "my-server")
/// * `sans` - Subject Alternative Names (hostnames and IPs)
/// * `validity_days` - How many days the certificate should be valid
/// * `cert_path` - Output path for the PEM-encoded certificate
/// * `key_path` - Output path for the PEM-encoded private key
pub fn generate_self_signed(
    cn: &str,
    sans: &[String],
    validity_days: u32,
    cert_path: &Path,
    key_path: &Path,
) -> Result<()> {
    let key_pair = KeyPair::generate()
        .map_err(|e| eyre!("Failed to generate key pair: {}", e))?;

    let mut params = CertificateParams::default();

    // Set Common Name
    params.distinguished_name.push(DnType::CommonName, cn);

    // Set Subject Alternative Names
    for san in sans {
        // Try to parse as an IP address first, fall back to DNS name
        if let Ok(ip) = san.parse::<IpAddr>() {
            params.subject_alt_names.push(SanType::IpAddress(ip));
        } else {
            params.subject_alt_names.push(SanType::DnsName(
                san.as_str()
                    .try_into()
                    .map_err(|_| eyre!("Invalid DNS name in SAN: {}", san))?,
            ));
        }
    }

    // Set validity period
    let now = rcgen::date_time_ymd(2024, 1, 1);
    let not_after = now
        + std::time::Duration::from_secs(u64::from(validity_days) * 86400);
    params.not_before = now;
    params.not_after = not_after;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| eyre!("Failed to generate self-signed certificate: {}", e))?;

    // Write certificate
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| eyre!("Failed to create directory for cert {:?}: {}", parent, e))?;
    }
    std::fs::write(cert_path, cert.pem())
        .map_err(|e| eyre!("Failed to write certificate to {:?}: {}", cert_path, e))?;

    // Write private key
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| eyre!("Failed to create directory for key {:?}: {}", parent, e))?;
    }
    std::fs::write(key_path, key_pair.serialize_pem())
        .map_err(|e| eyre!("Failed to write private key to {:?}: {}", key_path, e))?;

    Ok(())
}

/// Check if auto-generation should run and generate the cert/key if needed.
///
/// Returns `Ok(true)` if certificates were generated, `Ok(false)` if they already existed.
pub fn maybe_generate_cert(config: &crate::config::TlsConfig) -> Result<bool> {
    if !config.auto_generate {
        return Ok(false);
    }

    let cert_missing = !config.cert_file.exists();
    let key_missing = !config.key_file.exists();

    if !cert_missing && !key_missing {
        return Ok(false);
    }

    warn!("⚠ Auto-generating a self-signed TLS certificate.");
    warn!(
        "  Certificate: {:?}  |  Key: {:?}",
        config.cert_file, config.key_file
    );
    warn!("  Self-signed certificates are NOT trusted by browsers by default.");
    warn!("  For production use, provide a certificate signed by a trusted CA.");

    generate_self_signed(
        &config.auto_generate_cn,
        &config.auto_generate_san,
        config.auto_generate_validity_days,
        &config.cert_file,
        &config.key_file,
    )?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let result = generate_self_signed(
            "localhost",
            &[
                "localhost".to_string(),
                "127.0.0.1".to_string(),
            ],
            365,
            &cert_path,
            &key_path,
        );

        assert!(result.is_ok(), "Certificate generation failed: {:?}", result);
        assert!(cert_path.exists(), "Certificate file not created");
        assert!(key_path.exists(), "Key file not created");

        // Verify the files are valid PEM
        let cert_content = std::fs::read_to_string(&cert_path).unwrap();
        assert!(cert_content.contains("BEGIN CERTIFICATE"));

        let key_content = std::fs::read_to_string(&key_path).unwrap();
        assert!(key_content.contains("BEGIN"));
    }

    #[test]
    fn test_maybe_generate_cert_skips_when_disabled() {
        let config = crate::config::TlsConfig {
            cert_file: std::path::PathBuf::from("/nonexistent/cert.pem"),
            key_file: std::path::PathBuf::from("/nonexistent/key.pem"),
            min_version: crate::config::TlsVersion::V1_3,
            ocsp_stapling: false,
            client_cert_mode: crate::config::ClientCertMode::None,
            client_ca_file: None,
            auto_generate: false,
            auto_generate_cn: "localhost".to_string(),
            auto_generate_san: vec![],
            auto_generate_validity_days: 365,
        };

        let result = maybe_generate_cert(&config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_maybe_generate_cert_generates_when_missing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let config = crate::config::TlsConfig {
            cert_file: cert_path.clone(),
            key_file: key_path.clone(),
            min_version: crate::config::TlsVersion::V1_3,
            ocsp_stapling: false,
            client_cert_mode: crate::config::ClientCertMode::None,
            client_ca_file: None,
            auto_generate: true,
            auto_generate_cn: "test-host".to_string(),
            auto_generate_san: vec!["localhost".to_string(), "127.0.0.1".to_string()],
            auto_generate_validity_days: 30,
        };

        let result = maybe_generate_cert(&config);
        assert!(result.is_ok(), "maybe_generate_cert failed: {:?}", result);
        assert_eq!(result.unwrap(), true);
        assert!(cert_path.exists());
        assert!(key_path.exists());
    }

    #[test]
    fn test_maybe_generate_cert_skips_when_existing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        // Pre-create the files
        std::fs::write(&cert_path, "existing cert").unwrap();
        std::fs::write(&key_path, "existing key").unwrap();

        let config = crate::config::TlsConfig {
            cert_file: cert_path.clone(),
            key_file: key_path.clone(),
            min_version: crate::config::TlsVersion::V1_3,
            ocsp_stapling: false,
            client_cert_mode: crate::config::ClientCertMode::None,
            client_ca_file: None,
            auto_generate: true,
            auto_generate_cn: "test-host".to_string(),
            auto_generate_san: vec![],
            auto_generate_validity_days: 30,
        };

        let result = maybe_generate_cert(&config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false); // Should NOT regenerate

        // Files should still have original content
        assert_eq!(std::fs::read_to_string(&cert_path).unwrap(), "existing cert");
    }
}
