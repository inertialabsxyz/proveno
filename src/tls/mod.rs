//! TLS attestation data structures and hash commitment.
//!
//! `TlsAttestationRecord` holds a DER-encoded certificate chain captured
//! during an HTTPS connection, plus a flag indicating whether the chain was
//! verified as P-256 ECDSA against the Mozilla root CA set.
//!
//! `compute_tls_attestation_hash` produces a SHA-256 hash over all verified
//! chains, or `[0u8; 32]` if no P-256-verified attestations are present.
//!
//! Hash layout for each verified record:
//! - 4-byte LE: number of certs in chain
//! - For each cert: 4-byte LE length, then DER bytes

use sha2::{Digest, Sha256};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// A TLS certificate chain captured during an HTTPS tool call.
///
/// The `cert_chain_der` field holds the raw DER-encoded certificates (leaf
/// first, root last). `p256_verified` is `true` only when the full chain has
/// been verified as P-256 ECDSA signed against a Mozilla root CA.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsAttestationRecord {
    /// DER-encoded certificate chain, leaf first.
    /// Empty when TLS attestation is unavailable (HTTP, non-P256, or failure).
    pub cert_chain_der: Vec<Vec<u8>>,
    /// `true` iff the chain was verified: P-256 ECDSA signatures valid,
    /// root cert is in the Mozilla root CA set.
    pub p256_verified: bool,
}

impl TlsAttestationRecord {
    /// Construct an unavailable attestation (plain HTTP, non-P256, or
    /// verification failure). `tls_attestation_hash` will be zero.
    pub fn unavailable() -> Self {
        TlsAttestationRecord { cert_chain_der: Vec::new(), p256_verified: false }
    }

    /// Construct a successfully verified P-256 attestation.
    pub fn p256_verified(cert_chain_der: Vec<Vec<u8>>) -> Self {
        TlsAttestationRecord { cert_chain_der, p256_verified: true }
    }
}

/// Compute the `tls_attestation_hash` from a slice of attestation records.
///
/// Returns `[0u8; 32]` when no record has `p256_verified == true`.
/// Otherwise returns SHA-256 over all verified cert chains in order.
pub fn compute_tls_attestation_hash(records: &[TlsAttestationRecord]) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut has_verified = false;

    for record in records {
        if !record.p256_verified {
            continue;
        }
        has_verified = true;
        h.update((record.cert_chain_der.len() as u32).to_le_bytes());
        for cert in &record.cert_chain_der {
            h.update((cert.len() as u32).to_le_bytes());
            h.update(cert);
        }
    }

    if has_verified { h.finalize().into() } else { [0u8; 32] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_records_gives_zero_hash() {
        assert_eq!(compute_tls_attestation_hash(&[]), [0u8; 32]);
    }

    #[test]
    fn unverified_record_gives_zero_hash() {
        let records = vec![TlsAttestationRecord::unavailable()];
        assert_eq!(compute_tls_attestation_hash(&records), [0u8; 32]);
    }

    #[test]
    fn verified_record_gives_nonzero_hash() {
        let records = vec![TlsAttestationRecord::p256_verified(vec![vec![1, 2, 3]])];
        let hash = compute_tls_attestation_hash(&records);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn hash_is_deterministic() {
        let records = vec![TlsAttestationRecord::p256_verified(vec![vec![1, 2, 3]])];
        let h1 = compute_tls_attestation_hash(&records);
        let h2 = compute_tls_attestation_hash(&records);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_chains_give_different_hashes() {
        let r1 = vec![TlsAttestationRecord::p256_verified(vec![vec![1, 2, 3]])];
        let r2 = vec![TlsAttestationRecord::p256_verified(vec![vec![4, 5, 6]])];
        assert_ne!(compute_tls_attestation_hash(&r1), compute_tls_attestation_hash(&r2));
    }

    #[test]
    fn unverified_record_does_not_affect_hash() {
        let verified = vec![TlsAttestationRecord::p256_verified(vec![vec![1, 2, 3]])];
        let with_unverified = vec![
            TlsAttestationRecord::p256_verified(vec![vec![1, 2, 3]]),
            TlsAttestationRecord::unavailable(),
        ];
        assert_eq!(
            compute_tls_attestation_hash(&verified),
            compute_tls_attestation_hash(&with_unverified),
        );
    }

    #[test]
    fn multiple_verified_records_hashed_in_order() {
        let r_ab = vec![
            TlsAttestationRecord::p256_verified(vec![vec![0xaa]]),
            TlsAttestationRecord::p256_verified(vec![vec![0xbb]]),
        ];
        let r_ba = vec![
            TlsAttestationRecord::p256_verified(vec![vec![0xbb]]),
            TlsAttestationRecord::p256_verified(vec![vec![0xaa]]),
        ];
        assert_ne!(compute_tls_attestation_hash(&r_ab), compute_tls_attestation_hash(&r_ba));
    }
}
