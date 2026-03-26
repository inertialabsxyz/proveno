//! Capture TLS handshake artifacts from rustls connections.
//!
//! Implements a custom `ServerCertVerifier` that wraps the default
//! `WebPkiServerVerifier` and captures certificate chains and
//! ServerCertificateVerify signatures for TLS attestation.

use std::sync::{Arc, Mutex};

use luai::host::tls_attestation::{DerCertificate, TlsAttestation, TlsSignatureScheme};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ring::default_provider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error as TlsError, SignatureScheme,
};

/// Captured TLS artifacts from a single connection.
#[derive(Debug, Clone)]
struct CapturedTlsData {
    cert_chain: Vec<DerCertificate>,
    /// The DER-encoded certificate passed to verify_tls13_signature
    /// (this is the cert whose pubkey verifies the signature).
    signing_cert_der: Vec<u8>,
    signature_scheme: Option<TlsSignatureScheme>,
    signature: Vec<u8>,
    /// The full message passed to verify_tls13_signature:
    /// 0x20*64 || "TLS 1.3, server CertificateVerify\0" || transcript_hash
    signed_message: Vec<u8>,
    hostname: String,
}

/// Thread-safe container for captured TLS data.
#[derive(Debug, Clone, Default)]
pub struct TlsCaptureStore {
    inner: Arc<Mutex<Vec<CapturedTlsData>>>,
}

impl TlsCaptureStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn push(&self, data: CapturedTlsData) {
        self.inner.lock().unwrap().push(data);
    }

    /// Take the last captured entry and convert to TlsAttestation.
    /// Returns None if no capture or if the signature scheme is unsupported.
    pub fn take_last(&self) -> Option<TlsAttestation> {
        let captured = self.inner.lock().unwrap().pop()?;
        let scheme = captured.signature_scheme?;

        // Use the signing cert as cert_chain[0] if available, to ensure the
        // pubkey extracted during verification matches the one that actually
        // verified the signature.
        let mut cert_chain = captured.cert_chain;
        if !captured.signing_cert_der.is_empty() && !cert_chain.is_empty() {
            cert_chain[0] = DerCertificate(captured.signing_cert_der);
        }

        Some(TlsAttestation {
            hostname: captured.hostname,
            cert_chain,
            signature_scheme: scheme,
            signature: captured.signature,
            signed_message: captured.signed_message,
        })
    }
}

/// A `ServerCertVerifier` that delegates to the real verifier but captures
/// the certificate chain and handshake signature for TLS attestation.
#[derive(Debug)]
struct CapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    store: TlsCaptureStore,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // Capture the certificate chain
        let mut chain = vec![DerCertificate(end_entity.to_vec())];
        for cert in intermediates {
            chain.push(DerCertificate(cert.to_vec()));
        }

        let hostname = match server_name {
            ServerName::DnsName(name) => name.as_ref().to_string(),
            _ => String::new(),
        };

        // Store partial capture (signature comes later in verify_tls13_signature)
        self.store.push(CapturedTlsData {
            cert_chain: chain,
            signing_cert_der: Vec::new(),
            signature_scheme: None,
            signature: Vec::new(),
            signed_message: Vec::new(),
            hostname,
        });

        // Delegate to real verifier
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // Capture the signature and scheme
        let scheme = match dss.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                Some(TlsSignatureScheme::EcdsaSecp256r1Sha256)
            }
            _ => None, // Unsupported scheme — attestation will be None
        };

        // Update the last captured entry with signature data
        {
            let mut entries = self.store.inner.lock().unwrap();
            if let Some(last) = entries.last_mut() {
                last.signing_cert_der = cert.to_vec();
                last.signature_scheme = scheme;
                last.signature = dss.signature().to_vec();
                last.signed_message = message.to_vec();
            }
        }

        // Delegate to real verifier
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // TLS 1.2 — delegate but don't capture (we only attest TLS 1.3)
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a reqwest blocking Client with TLS artifact capture enabled.
pub fn build_capturing_client(
    store: TlsCaptureStore,
    timeout_secs: u64,
) -> reqwest::blocking::Client {
    let provider = Arc::new(default_provider());

    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        )),
        provider.clone(),
    )
    .build()
    .expect("failed to build WebPki verifier");

    let capturing = Arc::new(CapturingVerifier {
        inner: verifier,
        store,
    });

    let tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(capturing)
        .with_no_client_auth();

    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .use_preconfigured_tls(tls_config)
        .build()
        .expect("failed to build capturing HTTP client")
}
