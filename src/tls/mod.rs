//! TLS attestation data structures and hash commitment.
//!
//! `TlsAttestationRecord` holds a DER-encoded certificate chain captured
//! during an HTTPS connection, plus metadata indicating whether the chain was
//! verified as P-256 ECDSA against the Mozilla root CA set.
//!
//! `compute_tls_attestation_hash` produces a Poseidon2 commitment over the
//! P-256 public-key halves (x || y) of every verified cert in the chain.
//! Both sides of the ZK pipeline commit to the same content: the Noir circuit
//! at `noir/src/main.nr` feeds the same pubkey bytes (one byte per Field) into
//! `Poseidon2::hash` and compares the result to `tls_attestation_hash`.
//!
//! The empty-record case is not zero-sentinel: it returns the canonical
//! Poseidon2 hash of the empty input vector, matching `Poseidon2::hash([], 0)`
//! in the circuit. `EMPTY_TLS_ATTESTATION_HASH` exposes that constant for
//! tests and downstream consumers that need to detect "no attestation".
//!
//! Hostname and `cert_not_after` are intentionally NOT part of the commitment:
//! the Noir circuit does not verify them, so binding them here would create a
//! Rust↔circuit mismatch on the proof-relevant content. Bind those out-of-band
//! (e.g. via a separate public input) if a future phase needs them.

pub mod verify;

use crate::host::poseidon2::{field_to_be_bytes32, poseidon2_hash, u8_to_field};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// A TLS certificate chain captured during an HTTPS tool call.
///
/// The `cert_chain_der` field holds the raw DER-encoded certificates (leaf
/// first, root last). `p256_verified` is `true` only when the full chain has
/// been verified as P-256 ECDSA signed against a Mozilla root CA and the
/// server hostname matches the leaf certificate's Subject Alternative Names.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsAttestationRecord {
    /// DER-encoded certificate chain, leaf first.
    /// Empty when TLS attestation is unavailable (HTTP, non-P256, or failure).
    pub cert_chain_der: Vec<Vec<u8>>,
    /// `true` iff the chain was verified: P-256 ECDSA signatures valid,
    /// root cert is in the Mozilla root CA set, and hostname matches leaf cert SANs.
    pub p256_verified: bool,
    /// The hostname this certificate was verified against.
    /// Empty string when attestation is unavailable.
    pub hostname: String,
    /// Unix timestamp (seconds) of the leaf certificate's `not_after` validity field.
    /// Zero when attestation is unavailable.
    pub cert_not_after: u64,
}

impl TlsAttestationRecord {
    /// Construct an unavailable attestation (plain HTTP, non-P256, hostname
    /// mismatch, or verification failure). `tls_attestation_hash` will be zero.
    pub fn unavailable() -> Self {
        TlsAttestationRecord {
            cert_chain_der: Vec::new(),
            p256_verified: false,
            hostname: String::new(),
            cert_not_after: 0,
        }
    }

    /// Construct a successfully verified P-256 attestation.
    pub fn p256_verified(
        cert_chain_der: Vec<Vec<u8>>,
        hostname: String,
        cert_not_after: u64,
    ) -> Self {
        TlsAttestationRecord {
            cert_chain_der,
            p256_verified: true,
            hostname,
            cert_not_after,
        }
    }
}

/// Compute the `tls_attestation_hash` from a slice of attestation records.
///
/// Returns `Poseidon2::hash([], 0)` (see `empty_tls_attestation_hash`) when no
/// record has `p256_verified == true` or no verifiable P-256 pubkey can be
/// extracted from any cert.
///
/// Otherwise: for each verified record, for each cert in chain order, extract
/// the SEC1 P-256 public-key affine coordinates (x, y) — 32 bytes each — and
/// feed all 64 bytes per cert into a Poseidon2 sponge as one Field per byte.
/// The result is serialized to `[u8; 32]` big-endian.
///
/// This matches the Noir circuit's TLS block byte-for-byte; both sides commit
/// to the same content. Certs whose DER cannot be parsed as P-256 contribute
/// nothing to the hash (matching the circuit's `if i < num_certs` predicate
/// over zero-padded slots).
pub fn compute_tls_attestation_hash(records: &[TlsAttestationRecord]) -> [u8; 32] {
    let mut fields = Vec::new();
    for record in records {
        if !record.p256_verified {
            continue;
        }
        for cert_der in &record.cert_chain_der {
            if let Some((x, y)) = verify::extract_p256_pubkey_xy(cert_der) {
                for b in x.iter().chain(y.iter()) {
                    fields.push(u8_to_field(*b));
                }
            }
        }
    }
    field_to_be_bytes32(poseidon2_hash(&fields))
}

/// The canonical "no attestation" hash: `Poseidon2::hash([], 0)` serialised to
/// `[u8; 32]` big-endian. Use this in place of `[0u8; 32]` when asserting that
/// no verified TLS attestation was captured.
pub fn empty_tls_attestation_hash() -> [u8; 32] {
    field_to_be_bytes32(poseidon2_hash(&[]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verified record carrying garbage DER bytes. Pubkey extraction fails so
    /// this contributes nothing to the hash — used to exercise the
    /// "unparseable cert is silently skipped" behaviour.
    fn verified_with_garbage_der(hostname: &str, not_after: u64) -> TlsAttestationRecord {
        TlsAttestationRecord::p256_verified(vec![vec![1, 2, 3]], hostname.to_string(), not_after)
    }

    #[test]
    fn empty_records_gives_canonical_empty_hash() {
        assert_eq!(
            compute_tls_attestation_hash(&[]),
            empty_tls_attestation_hash()
        );
    }

    #[test]
    fn unverified_record_gives_canonical_empty_hash() {
        let records = vec![TlsAttestationRecord::unavailable()];
        assert_eq!(
            compute_tls_attestation_hash(&records),
            empty_tls_attestation_hash()
        );
    }

    #[test]
    fn unparseable_der_is_silently_skipped() {
        // p256_verified == true, but DER bytes are garbage — the cert
        // contributes no fields, so the hash equals the empty case.
        let records = vec![verified_with_garbage_der("example.com", 9999999999)];
        assert_eq!(
            compute_tls_attestation_hash(&records),
            empty_tls_attestation_hash()
        );
    }

    #[test]
    fn hash_is_deterministic() {
        let records = vec![verified_with_garbage_der("example.com", 9999999999)];
        let h1 = compute_tls_attestation_hash(&records);
        let h2 = compute_tls_attestation_hash(&records);
        assert_eq!(h1, h2);
    }

    #[test]
    fn empty_hash_is_nonzero() {
        // The Poseidon2 sponge produces a non-zero digest on empty input via
        // the message-length IV, so the canonical sentinel is NOT [0; 32].
        assert_ne!(empty_tls_attestation_hash(), [0u8; 32]);
    }

    #[test]
    fn unverified_record_does_not_affect_hash() {
        // Only verified records contribute; unverified are skipped.
        let only_unverified = vec![TlsAttestationRecord::unavailable()];
        assert_eq!(
            compute_tls_attestation_hash(&only_unverified),
            compute_tls_attestation_hash(&[]),
        );
    }
}
