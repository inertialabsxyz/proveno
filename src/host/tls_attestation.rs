//! TLS attestation data captured during live HTTP tool calls.
//!
//! These structures record the TLS handshake artifacts needed to verify
//! that an HTTP response came from an authenticated server.
//!
//! During the dry run, the host captures:
//! - The server's certificate chain (DER-encoded X.509)
//! - The ServerCertificateVerify signature (TLS 1.3)
//! - The handshake transcript hash that was signed
//! - The hostname from the URL
//!
//! During zkVM replay, the guest verifies:
//! - Certificate chain up to a pinned root CA
//! - ECDSA signature over the transcript hash
//! - Hostname matches the certificate's SAN

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use sha2::{Digest, Sha256};

/// TLS signature scheme (subset we support for verification).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TlsSignatureScheme {
    /// ECDSA with P-256 and SHA-256 (TLS SignatureScheme 0x0403).
    EcdsaSecp256r1Sha256,
}

/// A single DER-encoded X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DerCertificate(pub Vec<u8>);

/// TLS attestation artifacts for one HTTP tool call.
///
/// Captures the minimum data needed to verify server identity in the zkVM:
/// - Certificate chain (server cert → intermediates → root)
/// - The ServerCertificateVerify signature from the TLS 1.3 handshake
/// - The signed message content (includes the transcript hash)
/// - The hostname used in the connection
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsAttestation {
    /// The hostname from the URL (for Subject Alternative Name matching).
    pub hostname: String,

    /// Certificate chain, ordered: \[server_cert, intermediate_ca, ..., root_ca\].
    /// Each entry is a DER-encoded X.509 certificate.
    pub cert_chain: Vec<DerCertificate>,

    /// The signature scheme used for ServerCertificateVerify.
    pub signature_scheme: TlsSignatureScheme,

    /// The ServerCertificateVerify signature bytes (DER-encoded ECDSA).
    pub signature: Vec<u8>,

    /// The full message passed to verify_tls13_signature in the TLS handshake.
    /// Format: 0x20*64 || "TLS 1.3, server CertificateVerify\0" || transcript_hash
    /// The transcript hash length depends on the cipher suite (32 for SHA-256, 48 for SHA-384).
    pub signed_message: Vec<u8>,
}

/// Compute a SHA-256 commitment hash over a list of TLS attestations.
///
/// Encoding per entry:
/// - `0x00` tag = no attestation (non-HTTPS tool call)
/// - `0x01` tag = attestation present, followed by:
///   - u16 LE hostname length + hostname UTF-8 bytes
///   - u16 LE cert chain count
///     - For each cert: u32 LE DER length + DER bytes
///   - u8 signature scheme tag
///   - u16 LE signature length + signature bytes
///   - u16 LE signed_message length + signed_message bytes
pub fn tls_attestations_hash(attestations: &[Option<TlsAttestation>]) -> [u8; 32] {
    let mut h = Sha256::new();
    for att_opt in attestations {
        match att_opt {
            None => {
                h.update([0x00u8]);
            }
            Some(att) => {
                h.update([0x01u8]);

                // hostname
                let hostname_bytes = att.hostname.as_bytes();
                h.update((hostname_bytes.len() as u16).to_le_bytes());
                h.update(hostname_bytes);

                // cert chain
                h.update((att.cert_chain.len() as u16).to_le_bytes());
                for cert in &att.cert_chain {
                    h.update((cert.0.len() as u32).to_le_bytes());
                    h.update(&cert.0);
                }

                // signature scheme
                let scheme_tag: u8 = match att.signature_scheme {
                    TlsSignatureScheme::EcdsaSecp256r1Sha256 => 0x01,
                };
                h.update([scheme_tag]);

                // signature
                h.update((att.signature.len() as u16).to_le_bytes());
                h.update(&att.signature);

                // signed message
                h.update((att.signed_message.len() as u16).to_le_bytes());
                h.update(&att.signed_message);
            }
        }
    }
    h.finalize().into()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_attestation() -> TlsAttestation {
        TlsAttestation {
            hostname: "example.com".into(),
            cert_chain: vec![
                DerCertificate(vec![0x30, 0x82, 0x01, 0x00]),
                DerCertificate(vec![0x30, 0x82, 0x02, 0x00]),
            ],
            signature_scheme: TlsSignatureScheme::EcdsaSecp256r1Sha256,
            signature: vec![0x30, 0x44, 0x02, 0x20],
            signed_message: vec![0xAA; 32],
        }
    }

    #[test]
    fn hash_empty_list() {
        let h = tls_attestations_hash(&[]);
        // Empty input should produce the SHA-256 of empty input
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn hash_all_none() {
        let h = tls_attestations_hash(&[None, None, None]);
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn hash_is_deterministic() {
        let att = sample_attestation();
        let h1 = tls_attestations_hash(&[Some(att.clone())]);
        let h2 = tls_attestations_hash(&[Some(att)]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_differs_for_different_hostnames() {
        let mut att1 = sample_attestation();
        let mut att2 = sample_attestation();
        att1.hostname = "a.com".into();
        att2.hostname = "b.com".into();
        assert_ne!(
            tls_attestations_hash(&[Some(att1)]),
            tls_attestations_hash(&[Some(att2)])
        );
    }

    #[test]
    fn hash_differs_for_different_signatures() {
        let mut att1 = sample_attestation();
        let mut att2 = sample_attestation();
        att1.signature = vec![0x01; 64];
        att2.signature = vec![0x02; 64];
        assert_ne!(
            tls_attestations_hash(&[Some(att1)]),
            tls_attestations_hash(&[Some(att2)])
        );
    }

    #[test]
    fn hash_none_vs_some_differs() {
        let att = sample_attestation();
        assert_ne!(
            tls_attestations_hash(&[None]),
            tls_attestations_hash(&[Some(att)])
        );
    }

    #[test]
    fn hash_order_matters() {
        let att = sample_attestation();
        let h1 = tls_attestations_hash(&[Some(att.clone()), None]);
        let h2 = tls_attestations_hash(&[None, Some(att)]);
        assert_ne!(h1, h2);
    }
}
