//! `luai-openvm-packager` — package an OpenVM app proof into a luai wire-format bundle.
//!
//! Usage:
//!   luai-openvm-packager <proof-file> <dry-result-json> <output-bundle>
//!
//! The OpenVM app proof binary format requires the full `openvm-sdk` to decode.
//! To avoid that heavyweight dependency, public inputs are read from `<dry-result-json>`,
//! which is produced by `luai-prover` prior to proving and contains the same commitments
//! that the guest reveals. The raw proof bytes are embedded in the bundle as the
//! `proof_blob` field.

use std::{env, fs, process};

use luai::zkvm::commitment::PublicInputs;
use luai_prover::prover::DryRunResult;
use luai_verifier::build_test_proof;

/// Build the luai wire-format proof bundle.
///
/// `public_inputs` are the six 32-byte commitments; `proof_bytes` is the raw
/// `luai-openvm.app.proof` file (opaque blob embedded as the proof_blob field).
pub fn package_proof(public_inputs: &PublicInputs, proof_bytes: &[u8]) -> Vec<u8> {
    build_test_proof(public_inputs, proof_bytes)
}

fn fmt_hash(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: luai-openvm-packager <proof-file> <dry-result-json> <output-bundle>");
        process::exit(1);
    }

    let proof_path = &args[1];
    let dry_result_path = &args[2];
    let output_path = &args[3];

    let proof_bytes = fs::read(proof_path).unwrap_or_else(|e| {
        eprintln!("error reading {proof_path}: {e}");
        process::exit(1);
    });

    let dry_result_json = fs::read_to_string(dry_result_path).unwrap_or_else(|e| {
        eprintln!("error reading {dry_result_path}: {e}");
        process::exit(1);
    });
    let dry_result: DryRunResult = serde_json::from_str(&dry_result_json).unwrap_or_else(|e| {
        eprintln!("error parsing {dry_result_path}: {e}");
        process::exit(1);
    });

    let pi = &dry_result.public_inputs;
    let bundle = package_proof(pi, &proof_bytes);

    fs::write(output_path, &bundle).unwrap_or_else(|e| {
        eprintln!("error writing {output_path}: {e}");
        process::exit(1);
    });

    println!("Proof bundle written: {} bytes", bundle.len());
    println!("  proof_blob_len:       {} bytes", proof_bytes.len());
    println!("  program_hash:         {}", fmt_hash(&pi.program_hash));
    println!("  input_hash:           {}", fmt_hash(&pi.input_hash));
    println!(
        "  tool_responses_hash:  {}",
        fmt_hash(&pi.tool_responses_hash)
    );
    println!("  output_hash:          {}", fmt_hash(&pi.output_hash));
    println!(
        "  tls_attestation_hash: {}",
        fmt_hash(&pi.tls_attestation_hash)
    );
    println!("  policy_hash:          {}", fmt_hash(&pi.policy_hash));
}

#[cfg(test)]
mod tests {
    use luai_verifier::verify_proof;

    use super::*;

    #[test]
    fn packager_roundtrip() {
        let policy_hash = [0xABu8; 32];
        let public_inputs = PublicInputs {
            program_hash: [1u8; 32],
            input_hash: [2u8; 32],
            tool_responses_hash: [3u8; 32],
            output_hash: [4u8; 32],
            tls_attestation_hash: [0u8; 32],
            policy_hash,
        };
        let mock_proof_bytes = b"mock-openvm-app-proof-bytes";

        let bundle = package_proof(&public_inputs, mock_proof_bytes);

        let result = verify_proof(&bundle, &public_inputs, &policy_hash)
            .expect("verify_proof must succeed on a correctly packaged bundle");
        assert!(result.verified);
        assert_eq!(result.public_inputs, public_inputs);
    }
}
