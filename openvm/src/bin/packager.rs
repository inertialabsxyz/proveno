//! `luai-openvm-packager` — package an OpenVM proof into a luai wire-format bundle.
//!
//! Usage (app proof):
//!   luai-openvm-packager <proof-file> <dry-result-json> <output-bundle>
//!
//! Usage (EVM / Groth16 proof):
//!   luai-openvm-packager --evm-json <proof.json> <dry-result-json> <output-bundle>
//!
//! For app proofs the raw proof bytes are embedded directly as the `proof_blob`.
//!
//! For EVM proofs `proof.json` contains the gnark BN254 Groth16 proof in the
//! standard JSON format produced by `cargo openvm prove evm`:
//! ```json
//! {
//!   "Ar":  { "X": "<decimal>", "Y": "<decimal>" },
//!   "Bs":  { "X": { "A0": "<decimal>", "A1": "<decimal>" },
//!             "Y": { "A0": "<decimal>", "A1": "<decimal>" } },
//!   "Krs": { "X": "<decimal>", "Y": "<decimal>" }
//! }
//! ```
//! The packager ABI-encodes the proof points as
//! `abi.encode(uint[2] pA, uint[2][2] pB, uint[2] pC)` (256 bytes) and embeds
//! that as the `proof_blob`.  The encoding follows the gnark Solidity verifier
//! convention: for G2 point Bs, the pair order is [A1, A0] to match the EVM
//! precompile expectation.
//!
//! If the value strings are hex (prefixed `0x`), hex decoding is used directly.

use std::{env, fs, process};

use luai::zkvm::commitment::PublicInputs;
use luai_prover::prover::DryRunResult;
use luai_verifier::build_test_proof;

/// Build the luai wire-format proof bundle from public inputs and raw proof bytes.
pub fn package_proof(public_inputs: &PublicInputs, proof_bytes: &[u8]) -> Vec<u8> {
    build_test_proof(public_inputs, proof_bytes)
}

fn fmt_hash(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a decimal or `0x`-prefixed hex string into a 32-byte big-endian array.
fn parse_uint256(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim().trim_matches('"');
    if s.starts_with("0x") || s.starts_with("0X") {
        let hex_str = &s[2..];
        let raw = hex::decode(hex_str).map_err(|e| format!("hex decode: {e}"))?;
        if raw.len() > 32 {
            return Err(format!("value too wide: {} bytes", raw.len()));
        }
        let mut out = [0u8; 32];
        out[32 - raw.len()..].copy_from_slice(&raw);
        return Ok(out);
    }
    // Decimal: long-multiply into 32-byte big-endian
    let mut out = [0u8; 32];
    for ch in s.chars() {
        let d = ch
            .to_digit(10)
            .ok_or_else(|| format!("invalid decimal digit '{ch}' in '{s}'"))?
            as u32;
        let mut carry = d;
        for byte in out.iter_mut().rev() {
            let cur = (*byte as u32) * 10 + carry;
            *byte = (cur & 0xFF) as u8;
            carry = cur >> 8;
        }
        if carry != 0 {
            return Err(format!("value overflows 256 bits: '{s}'"));
        }
    }
    Ok(out)
}

/// Parse the gnark Groth16 proof JSON produced by `cargo openvm prove evm` and
/// return 256 bytes of ABI-encoded proof calldata:
///   `abi.encode(uint[2] pA, uint[2][2] pB, uint[2] pC)`
///
/// G2 point Bs is encoded as [A1, A0] per the gnark Solidity verifier convention.
fn parse_evm_proof_json(json_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(json_bytes).map_err(|e| format!("JSON parse: {e}"))?;

    let get = |path: &[&str]| -> Result<[u8; 32], String> {
        let mut cur = &v;
        for key in path {
            cur = cur
                .get(key)
                .ok_or_else(|| format!("missing JSON field '{key}'"))?;
        }
        let s = cur
            .as_str()
            .ok_or_else(|| format!("field '{}' is not a string", path.last().unwrap()))?;
        parse_uint256(s)
    };

    // pA = [Ar.X, Ar.Y]
    let pa0 = get(&["Ar", "X"])?;
    let pa1 = get(&["Ar", "Y"])?;
    // pB = [[Bs.X.A1, Bs.X.A0], [Bs.Y.A1, Bs.Y.A0]]  (gnark convention: A1 before A0)
    let pb00 = get(&["Bs", "X", "A1"])?;
    let pb01 = get(&["Bs", "X", "A0"])?;
    let pb10 = get(&["Bs", "Y", "A1"])?;
    let pb11 = get(&["Bs", "Y", "A0"])?;
    // pC = [Krs.X, Krs.Y]
    let pc0 = get(&["Krs", "X"])?;
    let pc1 = get(&["Krs", "Y"])?;

    // ABI-encode: fixed-size arrays concatenate without offsets (256 bytes total)
    let mut enc = Vec::with_capacity(256);
    for chunk in [pa0, pa1, pb00, pb01, pb10, pb11, pc0, pc1] {
        enc.extend_from_slice(&chunk);
    }
    Ok(enc)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let (evm_mode, proof_path, dry_result_path, output_path) = if args.get(1).map(String::as_str)
        == Some("--evm-json")
    {
        if args.len() != 5 {
            eprintln!(
                "Usage: luai-openvm-packager --evm-json <proof.json> <dry-result-json> <output-bundle>"
            );
            process::exit(1);
        }
        (true, &args[2], &args[3], &args[4])
    } else {
        if args.len() != 4 {
            eprintln!("Usage: luai-openvm-packager <proof-file> <dry-result-json> <output-bundle>");
            eprintln!(
                "       luai-openvm-packager --evm-json <proof.json> <dry-result-json> <output-bundle>"
            );
            process::exit(1);
        }
        (false, &args[1], &args[2], &args[3])
    };

    let proof_bytes_raw = fs::read(proof_path).unwrap_or_else(|e| {
        eprintln!("error reading {proof_path}: {e}");
        process::exit(1);
    });

    let proof_blob = if evm_mode {
        parse_evm_proof_json(&proof_bytes_raw).unwrap_or_else(|e| {
            eprintln!("error parsing EVM proof JSON {proof_path}: {e}");
            process::exit(1);
        })
    } else {
        proof_bytes_raw
    };

    let dry_result_json = fs::read_to_string(dry_result_path).unwrap_or_else(|e| {
        eprintln!("error reading {dry_result_path}: {e}");
        process::exit(1);
    });
    let dry_result: DryRunResult = serde_json::from_str(&dry_result_json).unwrap_or_else(|e| {
        eprintln!("error parsing {dry_result_path}: {e}");
        process::exit(1);
    });

    let pi = &dry_result.public_inputs;
    let bundle = package_proof(pi, &proof_blob);

    fs::write(output_path, &bundle).unwrap_or_else(|e| {
        eprintln!("error writing {output_path}: {e}");
        process::exit(1);
    });

    println!("Proof bundle written: {} bytes", bundle.len());
    println!("  proof_blob_len:       {} bytes", proof_blob.len());
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
    println!(
        "  pi_cast_tuple: (0x{},0x{},0x{},0x{},0x{},0x{})",
        fmt_hash(&pi.program_hash),
        fmt_hash(&pi.input_hash),
        fmt_hash(&pi.tool_responses_hash),
        fmt_hash(&pi.output_hash),
        fmt_hash(&pi.tls_attestation_hash),
        fmt_hash(&pi.policy_hash),
    );
}

#[cfg(test)]
mod tests {
    use luai_verifier::verify_proof;

    use super::*;

    fn dummy_pi() -> PublicInputs {
        PublicInputs {
            program_hash: [1u8; 32],
            input_hash: [2u8; 32],
            tool_responses_hash: [3u8; 32],
            output_hash: [4u8; 32],
            tls_attestation_hash: [0u8; 32],
            policy_hash: [0xABu8; 32],
        }
    }

    #[test]
    fn packager_roundtrip() {
        let public_inputs = dummy_pi();
        let mock_proof_bytes = b"mock-openvm-app-proof-bytes";
        let bundle = package_proof(&public_inputs, mock_proof_bytes);
        let result = verify_proof(&bundle, &public_inputs, &public_inputs.policy_hash)
            .expect("verify_proof must succeed on a correctly packaged bundle");
        assert!(result.verified);
        assert_eq!(result.public_inputs, public_inputs);
    }

    #[test]
    fn parse_uint256_hex() {
        let got = parse_uint256("0x01").unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(got, expected);
    }

    #[test]
    fn parse_uint256_decimal() {
        let got = parse_uint256("256").unwrap();
        let mut expected = [0u8; 32];
        expected[30] = 1;
        assert_eq!(got, expected);
    }

    #[test]
    fn parse_evm_proof_json_roundtrip() {
        // Synthesise a minimal gnark-style proof JSON with decimal coords
        let json = serde_json::json!({
            "Ar": { "X": "1", "Y": "2" },
            "Bs": {
                "X": { "A0": "3", "A1": "4" },
                "Y": { "A0": "5", "A1": "6" }
            },
            "Krs": { "X": "7", "Y": "8" }
        })
        .to_string();

        let enc = parse_evm_proof_json(json.as_bytes()).unwrap();
        assert_eq!(enc.len(), 256);

        // pA[0] = Ar.X = 1, last byte of slot 0
        let mut slot = [0u8; 32];
        slot[31] = 1;
        assert_eq!(&enc[0..32], &slot);

        // pB[0][0] = Bs.X.A1 = 4
        slot[31] = 4;
        assert_eq!(&enc[64..96], &slot);

        // pC[0] = Krs.X = 7
        slot[31] = 7;
        assert_eq!(&enc[192..224], &slot);
    }
}
