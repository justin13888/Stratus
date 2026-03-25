//! mTLS (Mutual TLS) authentication provider.
//!
//! Extracts client identity from a verified TLS client certificate that was
//! injected as a `PeerCertificate` request extension by `MtlsAcceptor` in
//! `tls.rs`.

use crate::auth::provider::{AuthProvider, AuthResult};
use crate::auth::user::ReloadableUserStore;
use crate::config::MtlsUserMapping;
use axum::body::Body;
use http::Request;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::debug;
use x509_parser::prelude::*;

/// Request extension carrying the DER-encoded peer certificate injected after
/// the TLS handshake by `MtlsAcceptor`.
#[derive(Clone, Debug)]
pub struct PeerCertificate(pub Vec<u8>);

/// mTLS authentication provider.
///
/// Reads `PeerCertificate` from request extensions, extracts an identity
/// (CN, SAN email, or SAN DNS name) from the certificate, and looks that
/// identity up in the user database.
pub struct MtlsAuthProvider {
    user_store: Arc<ReloadableUserStore>,
    mapping: MtlsUserMapping,
}

impl MtlsAuthProvider {
    pub fn new(user_store: ReloadableUserStore, mapping: MtlsUserMapping) -> Self {
        Self {
            user_store: Arc::new(user_store),
            mapping,
        }
    }
}

/// Extract an identity string from a DER-encoded X.509 certificate.
fn extract_identity(cert_der: &[u8], mapping: MtlsUserMapping) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

    match mapping {
        MtlsUserMapping::Cn => cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok())
            .map(str::to_string),

        MtlsUserMapping::SanEmail => cert.extensions().iter().find_map(|ext| {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                san.general_names.iter().find_map(|gn| {
                    if let GeneralName::RFC822Name(email) = gn {
                        Some(email.to_string())
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        }),

        MtlsUserMapping::SanDns => cert.extensions().iter().find_map(|ext| {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                san.general_names.iter().find_map(|gn| {
                    if let GeneralName::DNSName(dns) = gn {
                        Some(dns.to_string())
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        }),
    }
}

impl AuthProvider for MtlsAuthProvider {
    fn authenticate(
        &self,
        request: &Request<Body>,
    ) -> Pin<Box<dyn Future<Output = AuthResult> + Send + '_>> {
        let cert = request.extensions().get::<PeerCertificate>().cloned();
        let user_store = Arc::clone(&self.user_store);
        let mapping = self.mapping;

        Box::pin(async move {
            let cert = match cert {
                Some(c) => c,
                None => {
                    debug!("mTLS: no client certificate in request extensions");
                    return AuthResult::NoCredentials;
                }
            };

            let identity = match extract_identity(&cert.0, mapping) {
                Some(id) => id,
                None => {
                    debug!("mTLS: failed to extract identity from client certificate");
                    return AuthResult::Failed("Invalid credentials".to_string());
                }
            };

            match user_store.get_user(&identity) {
                Some(user) => {
                    debug!("mTLS: authenticated as '{}'", identity);
                    AuthResult::Success(user)
                }
                None => {
                    debug!("mTLS: no user found for identity '{}'", identity);
                    AuthResult::Failed("Invalid credentials".to_string())
                }
            }
        })
    }

    fn scheme_name(&self) -> &'static str {
        "Certificate"
    }

    fn challenge(&self) -> String {
        // Client cert challenge is at the TLS layer; no HTTP challenge needed.
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::user::{ReloadableUserStore, UserStore};
    use std::collections::HashMap;

    fn make_request_with_cert(cert_der: Vec<u8>) -> Request<Body> {
        let mut req = Request::builder().body(Body::empty()).unwrap();
        req.extensions_mut().insert(PeerCertificate(cert_der));
        req
    }

    #[tokio::test]
    async fn test_mtls_no_cert_returns_no_credentials() {
        let store = UserStore::new();
        let provider = MtlsAuthProvider::new(ReloadableUserStore::new(store), MtlsUserMapping::Cn);

        let req = Request::builder().body(Body::empty()).unwrap();
        let result = provider.authenticate(&req).await;
        assert!(matches!(result, AuthResult::NoCredentials));
    }

    #[tokio::test]
    async fn test_mtls_invalid_cert_der_fails() {
        let store = UserStore::new();
        let provider = MtlsAuthProvider::new(ReloadableUserStore::new(store), MtlsUserMapping::Cn);

        let req = make_request_with_cert(vec![0x00, 0x01, 0x02]);
        let result = provider.authenticate(&req).await;
        assert!(matches!(result, AuthResult::Failed(_)));
    }

    #[test]
    fn test_extract_identity_invalid_der() {
        assert!(extract_identity(&[0x00, 0x01], MtlsUserMapping::Cn).is_none());
    }

    #[tokio::test]
    async fn test_mtls_unknown_cn_fails() {
        // Generate a real self-signed cert for testing
        use rcgen::{CertificateParams, KeyPair};

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "testuser");
        let cert = params.self_signed(&key).unwrap();
        let cert_der = cert.der().to_vec();

        // User store does NOT have "testuser"
        let store = UserStore::new();
        let provider = MtlsAuthProvider::new(ReloadableUserStore::new(store), MtlsUserMapping::Cn);

        let req = make_request_with_cert(cert_der);
        let result = provider.authenticate(&req).await;
        assert!(matches!(result, AuthResult::Failed(_)));
    }

    #[tokio::test]
    async fn test_mtls_known_cn_succeeds() {
        use rcgen::{CertificateParams, KeyPair};

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "alice");
        let cert = params.self_signed(&key).unwrap();
        let cert_der = cert.der().to_vec();

        let mut store = UserStore::new();
        store.add_user("alice".to_string(), "hash".to_string(), vec![], HashMap::new());
        let provider = MtlsAuthProvider::new(ReloadableUserStore::new(store), MtlsUserMapping::Cn);

        let req = make_request_with_cert(cert_der);
        let result = provider.authenticate(&req).await;
        assert!(matches!(result, AuthResult::Success(_)));
        if let AuthResult::Success(user) = result {
            assert_eq!(user.username, "alice");
        }
    }
}
