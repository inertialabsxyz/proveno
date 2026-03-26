//! Public inputs and commitment hashes for zkVM proofs.
//!
//! The `PublicInputs` struct is committed to by the zkVM guest and verified
//! by the host. It ties together all the cryptographic commitments of one
//! agent execution:
//!   - which program ran (`program_hash`)
//!   - what input it received (`input_hash`)
//!   - which tool responses were consumed (`tool_responses_hash`)
//!   - what outputs were produced (`output_hash`)

use sha2::{Digest, Sha256};

use crate::{
    host::{
        canonicalize::canonical_serialize,
        tape::{OracleTape, TapeEntry},
        tls_attestation::tls_attestations_hash,
    },
    types::value::LuaValue,
    vm::engine::VmOutput,
};

/// The five public commitments attested by a zkVM proof.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicInputs {
    /// SHA-256 of the canonical encoding of all `FunctionProto`s in the program.
    /// Equal to `CompiledProgram::program_hash`.
    pub program_hash: [u8; 32],

    /// SHA-256 of `canonical_serialize(input_value)`.
    pub input_hash: [u8; 32],

    /// SHA-256 commitment over all oracle tape entries (from `OracleTape::commitment_hash()`).
    pub tool_responses_hash: [u8; 32],

    /// SHA-256 over `return_value || length-prefixed logs || transcript entries`.
    pub output_hash: [u8; 32],

    /// SHA-256 commitment over TLS attestation data for all tool calls.
    /// `[0u8; 32]` (SHA-256 of empty input) when no TLS attestations are present.
    pub tls_attestation_hash: [u8; 32],
}

/// Compute the `input_hash` for a given `LuaValue`.
///
/// SHA-256 of `canonical_serialize(v)`. If serialization fails (e.g. function
/// value passed in), falls back to the hash of `"null"`.
pub fn hash_input(v: &LuaValue) -> [u8; 32] {
    let bytes = canonical_serialize(v).unwrap_or_else(|_| b"null".to_vec());
    Sha256::digest(&bytes).into()
}

/// Compute the `output_hash` for a `VmOutput`.
///
/// Hash layout:
/// 1. `canonical_serialize(return_value)` bytes
/// 2. For each log: `u32_le(len) || utf8_bytes`
/// 3. For each transcript record: `tag(1) || u32_le(len) || payload`
///    - Success: tag=0x00, payload=`response_canonical`
///    - Error:   tag=0x01, payload=`error_message` as UTF-8 bytes
pub fn hash_output(output: &VmOutput) -> [u8; 32] {
    let mut h = Sha256::new();

    // 1. Return value
    h.update(
        canonical_serialize(&output.return_value).unwrap_or_else(|_| b"null".to_vec()),
    );

    // 2. Logs: length-prefixed
    for log in &output.logs {
        h.update((log.len() as u32).to_le_bytes());
        h.update(log.as_bytes());
    }

    // 3. Transcript: framed identically to OracleTape entries (tag || len_le4 || payload)
    for record in &output.transcript {
        if record.error_message.is_empty() {
            h.update([0x00u8]);
            h.update((record.response_canonical.len() as u32).to_le_bytes());
            h.update(&record.response_canonical);
        } else {
            let msg = record.error_message.as_bytes();
            h.update([0x01u8]);
            h.update((msg.len() as u32).to_le_bytes());
            h.update(msg);
        }
    }

    h.finalize().into()
}

/// Build `PublicInputs` from all the components of an execution.
pub fn compute_public_inputs(
    program_hash: [u8; 32],
    input_value: &LuaValue,
    oracle_tape: &OracleTape,
    output: &VmOutput,
) -> PublicInputs {
    // Extract TLS attestations from tape entries for commitment
    let tls_attestations: Vec<_> = oracle_tape
        .entries
        .iter()
        .map(|e| match e {
            TapeEntry::Ok { tls_attestation, .. } => tls_attestation.clone(),
            TapeEntry::Err(_) => None,
        })
        .collect();

    PublicInputs {
        program_hash,
        input_hash: hash_input(input_value),
        tool_responses_hash: oracle_tape.commitment_hash(),
        output_hash: hash_output(output),
        tls_attestation_hash: tls_attestations_hash(&tls_attestations),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::tls_attestation::tls_attestations_hash;

    fn make_output(ret: LuaValue) -> VmOutput {
        VmOutput {
            return_value: ret,
            logs: vec![],
            gas_used: 0,
            memory_used: 0,
            transcript: vec![],
        }
    }

    #[test]
    fn hash_input_nil_is_deterministic() {
        let h1 = hash_input(&LuaValue::Nil);
        let h2 = hash_input(&LuaValue::Nil);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn hash_input_differs_for_different_values() {
        let h1 = hash_input(&LuaValue::Integer(1));
        let h2 = hash_input(&LuaValue::Integer(2));
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_output_deterministic() {
        let out = make_output(LuaValue::Nil);
        let h1 = hash_output(&out);
        let h2 = hash_output(&out);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_output_includes_return_value() {
        let out1 = make_output(LuaValue::Integer(1));
        let out2 = make_output(LuaValue::Integer(2));
        assert_ne!(hash_output(&out1), hash_output(&out2));
    }

    #[test]
    fn hash_output_includes_logs() {
        let mut out1 = make_output(LuaValue::Nil);
        out1.logs.push("hello".to_string());
        let out2 = make_output(LuaValue::Nil);
        assert_ne!(hash_output(&out1), hash_output(&out2));
    }

    #[test]
    fn compute_public_inputs_fields() {
        let tape = OracleTape::new();
        let output = make_output(LuaValue::Nil);
        let program_hash = [1u8; 32];
        let input = LuaValue::Integer(42);

        let pi = compute_public_inputs(program_hash, &input, &tape, &output);
        assert_eq!(pi.program_hash, program_hash);
        assert_eq!(pi.input_hash, hash_input(&input));
        assert_eq!(pi.tool_responses_hash, tape.commitment_hash());
        assert_eq!(pi.output_hash, hash_output(&output));
        // Empty tape → tls_attestation_hash is hash of empty input
        assert_eq!(pi.tls_attestation_hash, tls_attestations_hash(&[]));
    }
}
