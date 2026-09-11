//! Public inputs and commitment hashes for zkVM proofs.
//!
//! The `PublicInputs` struct is committed to by the zkVM guest and verified
//! by the host. It ties together all the cryptographic commitments of one
//! agent execution:
//!   - which program ran (`program_hash`)
//!   - what input it received (`input_hash`)
//!   - which tool responses were consumed (`tool_responses_hash`)
//!   - what outputs were produced (`output_hash`)
//!   - per-call provenance attestations bound to those responses (`attestation_hash`)
//!   - execution policy (`policy_hash`, Phase 2 stub)

use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::{
    host::{canonicalize::canonical_serialize, tape::OracleTape},
    types::value::LuaValue,
    vm::engine::VmOutput,
};

/// The public commitments attested by a zkVM proof.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicInputs {
    /// SHA-256 of the canonical encoding of all `FunctionProto`s in the program.
    /// Equal to `CompiledProgram::program_hash`.
    pub program_hash: [u8; 32],

    /// SHA-256 of `canonical_serialize(input_value)`.
    pub input_hash: [u8; 32],

    /// Commitment over all oracle tape entries, in order.
    ///
    /// The primitive depends on the proving backend, and is chosen by which
    /// constructor built this struct: Poseidon2 (`OracleTape::commitment_hash`)
    /// for the Noir path via [`compute_public_inputs`], SHA-256
    /// (`OracleTape::commitment_hash_sha256`) for zkVM backends via
    /// [`compute_public_inputs_sha256`]. The two are not interchangeable — a
    /// verifier must recompute with the same scheme the prover used.
    pub tool_responses_hash: [u8; 32],

    /// keccak256 of the canonical output payload `abi.encode(int256(return_value))`.
    ///
    /// This is the exact preimage and algorithm an on-chain consumer checks via
    /// `keccak256(outputPayload) == inputs.outputHash`, and it is bound
    /// *in-circuit* to the proven `return_value` (see `noir/src/main.nr`). It
    /// deliberately commits only the result the contract decodes — `logs` and
    /// `transcript` provenance is carried by `tool_responses_hash` /
    /// `attestation_hash`, not here.
    pub output_hash: [u8; 32],

    /// Bind-only provenance commitment: per-call Poseidon2 over each response
    /// leaf welded to the attestation blob the host sourced for it
    /// (`OracleTape::attestation_commitment()`). The attestation bytes are
    /// *committed, not verified* — production is delegated to external providers
    /// (signed feeds, zkTLS); a downstream consumer that trusts the provider
    /// verifies them. With no attestations this is the canonical
    /// `Poseidon2::hash([], 0)` digest, NOT `[0u8; 32]`.
    ///
    /// Under [`compute_public_inputs_sha256`] this is the SHA-256 scheme's
    /// equivalent (`OracleTape::attestation_commitment_sha256`), which is
    /// likewise a real digest rather than zero when no attestations are present.
    pub attestation_hash: [u8; 32],

    /// SHA-256 of the canonical encoding of the `OraclePolicy` document.
    /// Zero until Phase 2 populates this field.
    pub policy_hash: [u8; 32], // Phase 2 stub
}

/// Compute the `input_hash` for a given `LuaValue`.
///
/// SHA-256 of `canonical_serialize(v)`. If serialization fails (e.g. function
/// value passed in), falls back to the hash of `"null"`.
pub fn hash_input(v: &LuaValue) -> [u8; 32] {
    let bytes = canonical_serialize(v).unwrap_or_else(|_| b"null".to_vec());
    Sha256::digest(&bytes).into()
}

/// The proven `i64` return value for a `VmOutput`.
///
/// Mirrors the `proveno-noir` witness path exactly: an integer return value is
/// its own `i64`; anything else proves as `0` (the circuit binds `0` too).
fn return_value_i64(v: &LuaValue) -> i64 {
    match v {
        LuaValue::Integer(n) => *n,
        _ => 0,
    }
}

/// The canonical output payload for a proven `i64`: `abi.encode(int256(n))`.
///
/// A single 32-byte big-endian, two's-complement (sign-extended) word — exactly
/// what Solidity `abi.decode(payload, (int256))` reads back. This is the
/// preimage the circuit hashes in-circuit and the contract hashes on-chain.
pub fn abi_encode_int256(n: i64) -> [u8; 32] {
    let mut out = if n < 0 { [0xffu8; 32] } else { [0u8; 32] };
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

/// Compute the `output_hash` for a `VmOutput`.
///
/// `keccak256(abi.encode(int256(return_value)))` — the canonical output payload
/// a consumer contract decodes, bound in-circuit to the proven `return_value`.
/// Only the result is committed here; `logs`/`transcript` are deliberately not
/// mixed in (their provenance lives in `tool_responses_hash` /
/// `attestation_hash`).
pub fn hash_output(output: &VmOutput) -> [u8; 32] {
    let payload = abi_encode_int256(return_value_i64(&output.return_value));
    Keccak256::digest(payload).into()
}

/// Build `PublicInputs` from all the components of an execution.
///
/// `policy_hash` is `[0u8; 32]` (no-policy stub). Use
/// `compute_public_inputs_with_policy` when a real policy is in force.
///
/// `attestation_hash` is derived from the oracle tape: each recorded response
/// is bound to the provenance attestation the host sourced for it (empty when
/// none). See `OracleTape::attestation_commitment`.
#[cfg(feature = "poseidon")]
pub fn compute_public_inputs(
    program_hash: [u8; 32],
    input_value: &LuaValue,
    oracle_tape: &OracleTape,
    output: &VmOutput,
) -> PublicInputs {
    PublicInputs {
        program_hash,
        input_hash: hash_input(input_value),
        tool_responses_hash: oracle_tape.commitment_hash(),
        output_hash: hash_output(output),
        attestation_hash: oracle_tape.attestation_commitment(),
        policy_hash: [0u8; 32],
    }
}

/// Build `PublicInputs` using the SHA-256 commitment scheme, for zkVM backends.
///
/// Identical to [`compute_public_inputs`] in every field except the two tape
/// commitments, which use SHA-256 rather than Poseidon2. `input_hash` is
/// already SHA-256 and `output_hash` is already keccak256 (both fixed by their
/// consumers), so only `tool_responses_hash` and `attestation_hash` differ.
///
/// Use this when proving with a RISC-V zkVM, where a software Poseidon2
/// permutation absorbing 3 bytes costs orders of magnitude more guest cycles
/// than an accelerated SHA-256 block. The resulting `PublicInputs` will NOT
/// match one built by [`compute_public_inputs`] for the same execution; pick
/// one scheme per verifier and stay on it.
///
/// `policy_hash` is `[0u8; 32]` (no-policy stub), matching
/// [`compute_public_inputs`].
pub fn compute_public_inputs_sha256(
    program_hash: [u8; 32],
    input_value: &LuaValue,
    oracle_tape: &OracleTape,
    output: &VmOutput,
) -> PublicInputs {
    PublicInputs {
        program_hash,
        input_hash: hash_input(input_value),
        tool_responses_hash: oracle_tape.commitment_hash_sha256(),
        output_hash: hash_output(output),
        attestation_hash: oracle_tape.attestation_commitment_sha256(),
        policy_hash: [0u8; 32],
    }
}

/// Build `PublicInputs` and populate `policy_hash` from the given policy.
///
/// Use this variant when running under a real `OraclePolicy`. The hash is
/// stable: same policy struct → same bytes on any machine.
#[cfg(all(feature = "poseidon", feature = "std"))]
pub fn compute_public_inputs_with_policy(
    program_hash: [u8; 32],
    input_value: &LuaValue,
    oracle_tape: &OracleTape,
    output: &VmOutput,
    policy: &crate::policy::OraclePolicy,
) -> PublicInputs {
    PublicInputs {
        program_hash,
        input_hash: hash_input(input_value),
        tool_responses_hash: oracle_tape.commitment_hash(),
        output_hash: hash_output(output),
        attestation_hash: oracle_tape.attestation_commitment(),
        policy_hash: policy.policy_hash(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_output(ret: LuaValue) -> VmOutput {
        VmOutput {
            return_value: ret,
            logs: vec![],
            gas_used: 0,
            memory_used: 0,
            transcript: vec![],
            trace: vec![],
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
    fn hash_output_ignores_logs_and_transcript() {
        // output_hash commits only the result the contract decodes; logs and
        // transcript provenance lives in tool_responses_hash / attestation_hash.
        let mut out1 = make_output(LuaValue::Integer(7));
        out1.logs.push("hello".to_string());
        let out2 = make_output(LuaValue::Integer(7));
        assert_eq!(hash_output(&out1), hash_output(&out2));
    }

    #[test]
    fn abi_encode_int256_known_vectors() {
        assert_eq!(abi_encode_int256(0), [0u8; 32]);

        let mut forty_two = [0u8; 32];
        forty_two[31] = 0x2a;
        assert_eq!(abi_encode_int256(42), forty_two);

        // -1 is all-ones in two's complement, sign-extended to 32 bytes.
        assert_eq!(abi_encode_int256(-1), [0xffu8; 32]);

        // 256 = 0x0100 occupies the two low-order bytes.
        let mut two_fifty_six = [0u8; 32];
        two_fifty_six[30] = 0x01;
        assert_eq!(abi_encode_int256(256), two_fifty_six);
    }

    #[test]
    fn hash_output_is_keccak_of_canonical_payload() {
        use sha3::{Digest, Keccak256};
        let out = make_output(LuaValue::Integer(42));
        let expected: [u8; 32] = Keccak256::digest(abi_encode_int256(42)).into();
        assert_eq!(hash_output(&out), expected);
    }

    #[test]
    fn hash_output_non_integer_proves_as_zero() {
        // Non-integer return values prove as i64 0, matching the witness path.
        assert_eq!(
            hash_output(&make_output(LuaValue::Nil)),
            hash_output(&make_output(LuaValue::Boolean(true)))
        );
    }

    #[cfg(feature = "poseidon")]
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
        // With no recorded calls, the attestation commitment is the tape's
        // canonical empty Poseidon2 digest (matching the circuit at num_tool_calls == 0).
        assert_eq!(pi.attestation_hash, tape.attestation_commitment());
        assert_eq!(pi.policy_hash, [0u8; 32]);
    }

    fn attested_tape() -> OracleTape {
        OracleTape {
            entries: vec![crate::host::tape::TapeEntry::Ok(
                b"{\"price\":100}".to_vec(),
            )],
            attestations: vec![b"sig".to_vec()],
        }
    }

    #[test]
    fn compute_public_inputs_sha256_fields() {
        let tape = attested_tape();
        let output = make_output(LuaValue::Integer(7));
        let program_hash = [1u8; 32];
        let input = LuaValue::Integer(42);

        let pi = compute_public_inputs_sha256(program_hash, &input, &tape, &output);
        assert_eq!(pi.program_hash, program_hash);
        assert_eq!(pi.input_hash, hash_input(&input));
        assert_eq!(pi.tool_responses_hash, tape.commitment_hash_sha256());
        assert_eq!(pi.output_hash, hash_output(&output));
        assert_eq!(pi.attestation_hash, tape.attestation_commitment_sha256());
        assert_eq!(pi.policy_hash, [0u8; 32]);
    }

    /// The two backends commit the same execution, but only the tape hashes
    /// change primitive. `input_hash` (SHA-256) and `output_hash` (keccak256)
    /// are fixed by their consumers and must be identical across backends.
    #[cfg(feature = "poseidon")]
    #[test]
    fn sha256_and_poseidon_public_inputs_differ_only_in_tape_hashes() {
        let tape = attested_tape();
        let output = make_output(LuaValue::Integer(7));
        let input = LuaValue::Integer(42);

        let p = compute_public_inputs([1u8; 32], &input, &tape, &output);
        let s = compute_public_inputs_sha256([1u8; 32], &input, &tape, &output);

        assert_eq!(p.program_hash, s.program_hash);
        assert_eq!(p.input_hash, s.input_hash);
        assert_eq!(p.output_hash, s.output_hash);
        assert_eq!(p.policy_hash, s.policy_hash);
        assert_ne!(p.tool_responses_hash, s.tool_responses_hash);
        assert_ne!(p.attestation_hash, s.attestation_hash);
    }

    /// Absence of attestations must still be a real commitment under SHA-256,
    /// the same property the Poseidon2 path has.
    #[test]
    fn compute_public_inputs_sha256_empty_tape_hashes_are_nonzero() {
        let tape = OracleTape::new();
        let output = make_output(LuaValue::Nil);
        let pi = compute_public_inputs_sha256([0u8; 32], &LuaValue::Nil, &tape, &output);
        assert_ne!(pi.tool_responses_hash, [0u8; 32]);
        assert_ne!(pi.attestation_hash, [0u8; 32]);
    }

    #[test]
    fn compute_public_inputs_sha256_is_deterministic() {
        let tape = attested_tape();
        let output = make_output(LuaValue::Integer(7));
        let a = compute_public_inputs_sha256([1u8; 32], &LuaValue::Integer(42), &tape, &output);
        let b = compute_public_inputs_sha256([1u8; 32], &LuaValue::Integer(42), &tape, &output);
        assert_eq!(a, b);
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn compute_public_inputs_policy_hash_is_zero_without_policy() {
        let tape = OracleTape::new();
        let output = make_output(LuaValue::Nil);
        let pi = compute_public_inputs([0u8; 32], &LuaValue::Nil, &tape, &output);
        assert_eq!(pi.policy_hash, [0u8; 32]);
    }

    #[cfg(all(feature = "poseidon", feature = "std"))]
    #[test]
    fn compute_public_inputs_with_policy_nonzero_hash() {
        use crate::policy::profiles::constrained_http_v1;

        let tape = OracleTape::new();
        let output = make_output(LuaValue::Nil);
        let policy = constrained_http_v1();

        let pi =
            compute_public_inputs_with_policy([0u8; 32], &LuaValue::Nil, &tape, &output, &policy);
        assert_ne!(pi.policy_hash, [0u8; 32]);
        assert_eq!(pi.policy_hash, policy.policy_hash());
    }

    #[cfg(all(feature = "poseidon", feature = "std"))]
    #[test]
    fn compute_public_inputs_with_policy_hash_stable() {
        use crate::policy::profiles::template_price_feed_v1;

        let tape = OracleTape::new();
        let output = make_output(LuaValue::Nil);
        let policy = template_price_feed_v1();

        let pi1 =
            compute_public_inputs_with_policy([0u8; 32], &LuaValue::Nil, &tape, &output, &policy);
        let pi2 =
            compute_public_inputs_with_policy([0u8; 32], &LuaValue::Nil, &tape, &output, &policy);
        assert_eq!(pi1.policy_hash, pi2.policy_hash);
    }
}
