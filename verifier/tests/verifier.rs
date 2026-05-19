use luai::zkvm::commitment::PublicInputs;
use luai_verifier::{VerifyError, build_test_proof, verify_proof};

fn make_public_inputs(policy_hash: [u8; 32]) -> PublicInputs {
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
fn verify_valid_proof_succeeds() {
    let policy_hash = [0xAAu8; 32];
    let pi = make_public_inputs(policy_hash);
    let proof = build_test_proof(&pi, b"mock_zk_proof_blob");
    let result = verify_proof(&proof, &pi, &policy_hash).expect("valid proof should succeed");
    assert!(result.verified);
    assert_eq!(result.public_inputs, pi);
}

#[test]
fn verify_wrong_policy_hash_fails() {
    let policy_hash = [0xAAu8; 32];
    let wrong_hash = [0xBBu8; 32];
    let pi = make_public_inputs(policy_hash);
    let proof = build_test_proof(&pi, b"mock_zk_proof_blob");
    let err = verify_proof(&proof, &pi, &wrong_hash).expect_err("wrong policy hash should fail");
    assert!(
        matches!(
            err,
            VerifyError::PolicyHashMismatch { got, expected }
                if got == policy_hash && expected == wrong_hash
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn verify_tampered_proof_fails() {
    let policy_hash = [0xAAu8; 32];
    let pi = make_public_inputs(policy_hash);
    let mut proof = build_test_proof(&pi, b"mock_zk_proof_blob");
    // Flip a byte inside the program_hash field (offset 5) — corrupts the
    // integrity checksum and causes the embedded public inputs to mismatch.
    proof[5] ^= 0xFF;
    let err = verify_proof(&proof, &pi, &policy_hash).expect_err("tampered proof should fail");
    assert_eq!(err, VerifyError::ProofInvalid, "unexpected error: {err}");
}
