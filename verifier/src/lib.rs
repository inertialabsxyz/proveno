//! Standalone verifier library for proveno ZK proofs.
//!
//! # Proof wire format (v1)
//!
//! ```text
//! [magic: 4]              b"prvn"
//! [version: 1]            0x01
//! [program_hash: 32]
//! [input_hash: 32]
//! [tool_responses_hash: 32]
//! [output_hash: 32]
//! [tls_attestation_hash: 32]
//! [policy_hash: 32]
//! [proof_blob_len: 4 LE]
//! [proof_blob: N]         OpenVM ZK proof bytes (or test fixture bytes)
//! [integrity: 32]         SHA-256(all preceding bytes)
//! ```
//!
//! The OpenVM ZK proof bytes are currently a placeholder. When a full OpenVM
//! proving pipeline is wired in, the `proof_blob` field carries the actual
//! `AggStarkProof` and the integrity check is supplemented by a real
//! cryptographic verification of that blob against the public inputs.

// Known stable policy hash for `template_price_feed_v1` (src/policy/profiles.rs):
//   0xe401364e121c0805290b1f060a6ed9a8dc796f86c17ead7632f01e0c1ec24687
// This value is deterministic: it is the SHA-256 of the canonical bytes of the
// policy (allowed domains sorted, methods sorted, all fields serialised in a
// fixed order).  Regenerate with: cargo run -p proveno-verifier --bin policy-hash
use proveno::zkvm::commitment::PublicInputs;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"prvn";
const VERSION: u8 = 0x01;
// magic(4) + version(1) + 6×hash(192) + proof_blob_len(4)
const HEADER_SIZE: usize = 4 + 1 + 32 * 6 + 4;
const INTEGRITY_SIZE: usize = 32;
const MIN_PROOF_LEN: usize = HEADER_SIZE + INTEGRITY_SIZE;

/// The outcome of a successful [`verify_proof`] call.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub verified: bool,
    pub public_inputs: PublicInputs,
    /// Raw output bytes from the execution. Empty in the current wire format;
    /// populated once the full OpenVM proof reveals the output payload.
    pub output_bytes: Vec<u8>,
}

/// Errors returned by [`verify_proof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The proof failed cryptographic or integrity verification.
    ProofInvalid,
    /// The proof's policy hash does not match the caller's expectation.
    PolicyHashMismatch { got: [u8; 32], expected: [u8; 32] },
    /// The proof bytes could not be parsed.
    MalformedInput(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::ProofInvalid => write!(f, "proof integrity verification failed"),
            VerifyError::PolicyHashMismatch { got, expected } => write!(
                f,
                "policy hash mismatch: got {}, expected {}",
                hex(got),
                hex(expected)
            ),
            VerifyError::MalformedInput(msg) => write!(f, "malformed proof input: {msg}"),
        }
    }
}

impl std::error::Error for VerifyError {}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify a proveno proof bundle.
///
/// Steps:
/// 1. Parse and integrity-check the proof wire format.
/// 2. Confirm the embedded public inputs match the caller-supplied `public_inputs`.
/// 3. Check `public_inputs.policy_hash == expected_policy_hash`.
///
/// Returns [`VerifyError::ProofInvalid`] if the proof bytes are structurally
/// invalid or the integrity checksum fails. Returns
/// [`VerifyError::PolicyHashMismatch`] if the proof is valid but the policy
/// hash does not match the caller's expectation.
pub fn verify_proof(
    proof: &[u8],
    public_inputs: &PublicInputs,
    expected_policy_hash: &[u8; 32],
) -> Result<VerificationResult, VerifyError> {
    if proof.len() < MIN_PROOF_LEN {
        return Err(VerifyError::MalformedInput(format!(
            "proof too short: {} bytes (minimum {MIN_PROOF_LEN})",
            proof.len()
        )));
    }

    if &proof[0..4] != MAGIC {
        return Err(VerifyError::MalformedInput(
            "invalid magic bytes".to_string(),
        ));
    }

    if proof[4] != VERSION {
        return Err(VerifyError::MalformedInput(format!(
            "unsupported proof version: {}",
            proof[4]
        )));
    }

    let mut offset = 5usize;
    let read32 = |off: &mut usize| -> [u8; 32] {
        let mut h = [0u8; 32];
        h.copy_from_slice(&proof[*off..*off + 32]);
        *off += 32;
        h
    };

    let embedded = PublicInputs {
        program_hash: read32(&mut offset),
        input_hash: read32(&mut offset),
        tool_responses_hash: read32(&mut offset),
        output_hash: read32(&mut offset),
        tls_attestation_hash: read32(&mut offset),
        policy_hash: read32(&mut offset),
    };

    let blob_len = u32::from_le_bytes(proof[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;

    let payload_end = offset + blob_len;
    if proof.len() < payload_end + INTEGRITY_SIZE {
        return Err(VerifyError::MalformedInput(format!(
            "proof truncated: declared blob_len={blob_len} but only {} bytes remain",
            proof.len().saturating_sub(offset)
        )));
    }

    // Integrity: SHA-256 of everything before the trailing hash
    let expected_integrity: [u8; 32] = Sha256::digest(&proof[..payload_end]).into();
    let got_integrity: [u8; 32] = proof[payload_end..payload_end + INTEGRITY_SIZE]
        .try_into()
        .unwrap();

    if expected_integrity != got_integrity {
        return Err(VerifyError::ProofInvalid);
    }

    // Embedded public inputs must match the caller-supplied ones
    if embedded != *public_inputs {
        return Err(VerifyError::ProofInvalid);
    }

    // Policy hash check
    if embedded.policy_hash != *expected_policy_hash {
        return Err(VerifyError::PolicyHashMismatch {
            got: embedded.policy_hash,
            expected: *expected_policy_hash,
        });
    }

    Ok(VerificationResult {
        verified: true,
        public_inputs: embedded,
        output_bytes: vec![],
    })
}

/// Build a proof fixture for testing.
///
/// Produces a well-formed wire-format proof for the given `public_inputs`.
/// The `proof_blob` can be any bytes; it plays the role of the future OpenVM
/// ZK proof and is included in the integrity hash.
pub fn build_test_proof(public_inputs: &PublicInputs, proof_blob: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MIN_PROOF_LEN + proof_blob.len());
    buf.extend_from_slice(MAGIC);
    buf.push(VERSION);
    buf.extend_from_slice(&public_inputs.program_hash);
    buf.extend_from_slice(&public_inputs.input_hash);
    buf.extend_from_slice(&public_inputs.tool_responses_hash);
    buf.extend_from_slice(&public_inputs.output_hash);
    buf.extend_from_slice(&public_inputs.tls_attestation_hash);
    buf.extend_from_slice(&public_inputs.policy_hash);
    buf.extend_from_slice(&(proof_blob.len() as u32).to_le_bytes());
    buf.extend_from_slice(proof_blob);
    let integrity: [u8; 32] = Sha256::digest(&buf).into();
    buf.extend_from_slice(&integrity);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pi(policy_hash: [u8; 32]) -> PublicInputs {
        PublicInputs {
            program_hash: [1u8; 32],
            input_hash: [2u8; 32],
            tool_responses_hash: [3u8; 32],
            output_hash: [4u8; 32],
            tls_attestation_hash: [0u8; 32],
            policy_hash,
        }
    }

    #[test]
    fn build_and_verify_roundtrip() {
        let policy_hash = [0xABu8; 32];
        let public_inputs = pi(policy_hash);
        let proof = build_test_proof(&public_inputs, b"blob");
        let result = verify_proof(&proof, &public_inputs, &policy_hash).unwrap();
        assert!(result.verified);
        assert_eq!(result.public_inputs, public_inputs);
    }

    #[test]
    fn too_short_is_malformed() {
        assert!(matches!(
            verify_proof(&[0u8; 10], &pi([0; 32]), &[0; 32]),
            Err(VerifyError::MalformedInput(_))
        ));
    }

    #[test]
    fn bad_magic_is_malformed() {
        let public_inputs = pi([0u8; 32]);
        let mut proof = build_test_proof(&public_inputs, b"");
        proof[0] = 0xFF;
        assert!(matches!(
            verify_proof(&proof, &public_inputs, &[0; 32]),
            Err(VerifyError::MalformedInput(_))
        ));
    }

    #[test]
    fn mismatched_public_inputs_is_proof_invalid() {
        let policy_hash = [0xAAu8; 32];
        let pi_a = pi(policy_hash);
        let pi_b = PublicInputs {
            program_hash: [99u8; 32],
            ..pi_a.clone()
        };
        // proof commits to pi_a, but we claim pi_b
        let proof = build_test_proof(&pi_a, b"blob");
        assert_eq!(
            verify_proof(&proof, &pi_b, &policy_hash).unwrap_err(),
            VerifyError::ProofInvalid
        );
    }
}
