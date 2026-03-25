//! TLS configuration and setup
//!
//! This module builds a fully custom `rustls::ServerConfig` rather than using
//! axum-server's convenience helpers, giving full control over:
//!
//! - TLS protocol version enforcement (1.2 vs 1.3)
//! - ALPN protocol negotiation (h2 / http/1.1)
//! - Client certificate verification (mTLS)
//! - Certificate hot-reloading

use crate::auth::mtls::PeerCertificate;
use crate::config::{ClientCertMode, TlsConfig, TlsVersion};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use eyre::{Result, eyre};
use http::Request;
use notify::{Event, EventKind, RecursiveMode, Watcher as NotifyWatcher};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls_pemfile::{certs, private_key};
use std::future::Future;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tower::Service;
use tracing::{error, info};

/// Configure Rustls from TLS configuration.
///
/// Builds a full `rustls::ServerConfig` with:
/// - TLS version enforcement based on `config.min_version`
/// - ALPN protocols (`h2`, `http/1.1`)
/// - Optional client certificate verification for mTLS
pub async fn configure_rustls(config: &TlsConfig) -> Result<RustlsConfig> {
    validate_tls_files(&config.cert_file, &config.key_file)?;

    let server_config = build_server_config(config)?;
    RustlsConfig::from_config(Arc::new(server_config))
        .await
        .map_err(|e| eyre!("Failed to build RustlsConfig: {}", e))
}

/// Build the underlying `rustls::ServerConfig`.
///
/// This is separate from `configure_rustls()` so it can be called by the cert
/// hot-reload watcher without requiring an async context.
pub fn build_server_config(config: &TlsConfig) -> Result<ServerConfig> {
    let cert_chain = load_certs(&config.cert_file)?;
    let private_key = load_private_key(&config.key_file)?;

    // Configure client certificate verification (mTLS)
    let builder = ServerConfig::builder_with_protocol_versions(tls_versions(config.min_version));

    let mut server_config = match config.client_cert_mode {
        ClientCertMode::None => builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| eyre!("Invalid certificate or private key: {}", e))?,

        ClientCertMode::Optional | ClientCertMode::Required => {
            let ca_file = config.client_ca_file.as_ref().ok_or_else(|| {
                eyre!("client_ca_file must be set when client_cert_mode is optional or required")
            })?;

            let ca_certs = load_certs(ca_file)?;
            let mut root_store = rustls::RootCertStore::empty();
            for cert in ca_certs {
                root_store
                    .add(cert)
                    .map_err(|e| eyre!("Failed to add CA cert to root store: {}", e))?;
            }

            let verifier = WebPkiClientVerifier::builder(Arc::new(root_store));
            let verifier = if config.client_cert_mode == ClientCertMode::Optional {
                verifier.allow_unauthenticated()
            } else {
                verifier
            };
            let verifier = verifier
                .build()
                .map_err(|e| eyre!("Failed to build client cert verifier: {}", e))?;

            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| eyre!("Invalid certificate or private key: {}", e))?
        }
    };

    // Set ALPN protocols: prefer HTTP/2, fall back to HTTP/1.1
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(server_config)
}

/// Return the set of supported TLS protocol versions based on the configured minimum
fn tls_versions(min: TlsVersion) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match min {
        TlsVersion::V1_2 => rustls::DEFAULT_VERSIONS, // TLS 1.2 and 1.3
        TlsVersion::V1_3 => &[&rustls::version::TLS13],
    }
}

/// Load PEM-encoded certificate chain from a file
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| eyre!("Failed to open certificate file {:?}: {}", path, e))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer> = certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| eyre!("Failed to parse certificates from {:?}: {}", path, e))?;
    if certs.is_empty() {
        return Err(eyre!("No certificates found in {:?}", path));
    }
    Ok(certs)
}

/// Load PEM-encoded private key from a file
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .map_err(|e| eyre!("Failed to open key file {:?}: {}", path, e))?;
    let mut reader = BufReader::new(file);
    private_key(&mut reader)
        .map_err(|e| eyre!("Failed to parse private key from {:?}: {}", path, e))?
        .ok_or_else(|| eyre!("No private key found in {:?}", path))
}

/// Start watching TLS certificate and key files for changes and reload them automatically.
///
/// Uses the same debounced watcher pattern as the user database hot-reloader.
/// On change, rebuilds the full `ServerConfig` and calls `RustlsConfig::reload_from_config()`.
/// If the reload fails, the existing configuration is kept (fail-safe).
pub fn start_cert_watcher(
    rustls_config: RustlsConfig,
    tls_config: TlsConfig,
) -> Result<(), notify::Error> {
    info!(
        "Starting TLS cert watcher for {:?} / {:?}",
        tls_config.cert_file, tls_config.key_file
    );

    let cert_path: PathBuf = tls_config
        .cert_file
        .canonicalize()
        .unwrap_or_else(|_| tls_config.cert_file.clone());
    let key_path: PathBuf = tls_config
        .key_file
        .canonicalize()
        .unwrap_or_else(|_| tls_config.key_file.clone());

    // Watch the parent directories (individual files can be unreliable)
    let cert_parent = cert_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let key_parent = key_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(100);

    let tx_clone = tx.clone();
    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            let _ = tx_clone.blocking_send(event);
        }
    })?;

    watcher.watch(&cert_parent, RecursiveMode::NonRecursive)?;
    // Only watch key_parent separately if it's different from cert_parent
    if key_parent != cert_parent {
        watcher.watch(&key_parent, RecursiveMode::NonRecursive)?;
    }

    info!("TLS cert watcher started");

    tokio::spawn(async move {
        let _watcher = watcher;
        let debounce_duration = Duration::from_millis(500);
        let mut debounce_timer: Option<tokio::time::Instant> = None;

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    let relevant = event.paths.iter().any(|p| {
                        let canonical = p.canonicalize().unwrap_or_else(|_| p.clone());
                        canonical == cert_path
                            || canonical == key_path
                            || p.file_name() == cert_path.file_name()
                            || p.file_name() == key_path.file_name()
                    });

                    if relevant && matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        debounce_timer = Some(tokio::time::Instant::now() + debounce_duration);
                    }
                }
                _ = async {
                    if let Some(deadline) = debounce_timer {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }, if debounce_timer.is_some() => {
                    debounce_timer = None;
                    info!("TLS cert/key file changed, reloading...");

                    match build_server_config(&tls_config) {
                        Ok(new_config) => {
                            rustls_config.reload_from_config(Arc::new(new_config));
                            info!("TLS certificates reloaded successfully");
                        }
                        Err(e) => {
                            error!("Failed to reload TLS certificates: {}", e);
                            error!("Keeping existing TLS configuration");
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

// ── mTLS acceptor ──────────────────────────────────────────────────────────

/// Axum-server acceptor that performs the TLS handshake via `RustlsAcceptor`
/// and then injects the verified peer certificate (if any) as a
/// `PeerCertificate` request extension so that `MtlsAuthProvider` can read it.
#[derive(Clone)]
pub struct MtlsAcceptor {
    inner: RustlsAcceptor,
}

impl MtlsAcceptor {
    pub fn new(config: RustlsConfig) -> Self {
        Self {
            inner: RustlsAcceptor::new(config),
        }
    }
}

impl<S: Send + 'static> Accept<TcpStream, S> for MtlsAcceptor {
    type Stream = TlsStream<TcpStream>;
    type Service = PeerCertInjectingService<S>;
    type Future = Pin<
        Box<
            dyn Future<Output = io::Result<(TlsStream<TcpStream>, PeerCertInjectingService<S>)>>
                + Send,
        >,
    >;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            let (tls_stream, svc) = inner.accept(stream, service).await?;
            // Extract peer cert from the completed TLS handshake (None if not mTLS)
            let cert = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|c| PeerCertificate(c.as_ref().to_vec()));
            Ok((tls_stream, PeerCertInjectingService { inner: svc, cert }))
        })
    }
}

/// Tower service wrapper that inserts a `PeerCertificate` extension into every
/// request before delegating to the inner service.
#[derive(Clone)]
pub struct PeerCertInjectingService<S> {
    inner: S,
    cert: Option<PeerCertificate>,
}

impl<S, B> Service<Request<B>> for PeerCertInjectingService<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if let Some(cert) = self.cert.clone() {
            req.extensions_mut().insert(cert);
        }
        self.inner.call(req)
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

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

    #[test]
    fn test_tls_versions_v13_only() {
        let versions = tls_versions(TlsVersion::V1_3);
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0], &rustls::version::TLS13);
    }

    #[test]
    fn test_tls_versions_v12_includes_both() {
        let versions = tls_versions(TlsVersion::V1_2);
        // DEFAULT_VERSIONS includes both TLS 1.2 and 1.3
        assert!(versions.len() >= 2);
    }
}
