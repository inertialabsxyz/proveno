//! `GuestInput` — the serializable bundle fed into the zkVM guest.
//!
//! The guest reads one `GuestInput`, re-executes the program with a `TapeHost`
//! for tool calls, computes the `PublicInputs`, and commits them to the journal.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::{
    compiler::proto::CompiledProgram,
    host::tape::{OracleTape, TapeHost},
    noir::encoder::compute_program_hash_sha256,
    types::value::LuaValue,
    vm::{
        engine::{Vm, VmConfig, VmOutput},
        gas::VmError,
    },
    zkvm::commitment::{PublicInputs, compute_public_inputs_sha256_with_policy_hash},
};
use sha2::{Digest, Sha256};

/// Everything the zkVM guest needs to replay an agent execution deterministically.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GuestInput {
    /// The compiled Lua program (bytecode + program_hash).
    pub program: CompiledProgram,
    /// The input value passed to the program's top-level function.
    pub input_value: LuaValue,
    /// Pre-recorded oracle tape of tool responses.
    pub oracle_tape: OracleTape,
    /// VM resource limits (must be identical to the dry-run config).
    pub config: VmConfig,
    /// Tool names registered in the dry run (used to build the ToolRegistry inside the guest).
    pub tool_names: Vec<String>,
    /// `OraclePolicy::canonical_bytes()` of the policy in force, or empty when
    /// no policy was attached.
    ///
    /// The guest hashes these itself rather than being handed a `policy_hash`,
    /// so the committed hash provably corresponds to this document and a
    /// prover cannot assert an unrelated one. The policy is carried as bytes
    /// because `OraclePolicy` needs `serde_json` for its schemas and the guest
    /// is `no_std`.
    #[cfg_attr(feature = "serde", serde(default))]
    pub policy_canonical: Vec<u8>,
}

impl GuestInput {
    /// Replay the program against the oracle tape and compute the public inputs.
    ///
    /// This is the whole of what a zkVM guest proves, and the host driver calls
    /// the identical function to predict what the guest will reveal. Keeping it
    /// in one place is the point: if host and guest computed these separately
    /// they could drift, and a drift shows up only as an unverifiable proof.
    ///
    /// Every commitment is derived from data in `self`, and `program_hash` is
    /// **recomputed from the bytecode** rather than read from
    /// `self.program.program_hash`. That field arrives from `proveno-compiler`,
    /// which builds with `poseidon` and therefore stores the Poseidon2 hash;
    /// using it here would both mix schemes and let a prover assert a program
    /// hash unrelated to what actually ran.
    ///
    /// Replay uses a [`TapeHost`], so no external calls happen and the run is
    /// bit-identical to the host dry run that produced the tape.
    ///
    /// `policy_hash` is SHA-256 of [`Self::policy_canonical`], matching
    /// `OraclePolicy::policy_hash` byte for byte, and is all-zero when no
    /// policy is attached. This **binds** the policy document, it does not
    /// verify compliance: the policy is enforced host-side during the dry run
    /// via `ToolRegistry::with_policy`, and the guest does not re-check it.
    /// Same boundary as `attestation_hash`.
    ///
    /// Not bound: [`VmConfig`]. The prover picks the gas and memory limits,
    /// which decide whether execution completes or aborts. Committing to the
    /// config is follow-on work.
    pub fn replay_public_inputs(&self) -> Result<(VmOutput, PublicInputs), VmError> {
        let program_hash = compute_program_hash_sha256(&self.program.prototypes);
        let mut vm = Vm::new(self.config.clone(), TapeHost::new(self.oracle_tape.clone()));
        let output = vm.execute(&self.program, self.input_value.clone())?;
        let policy_hash = if self.policy_canonical.is_empty() {
            [0u8; 32]
        } else {
            Sha256::digest(&self.policy_canonical).into()
        };
        let public_inputs = compute_public_inputs_sha256_with_policy_hash(
            program_hash,
            &self.input_value,
            &self.oracle_tape,
            &output,
            policy_hash,
        );
        Ok((output, public_inputs))
    }

    pub fn new(
        program: CompiledProgram,
        input_value: LuaValue,
        oracle_tape: OracleTape,
        config: VmConfig,
        tool_names: Vec<String>,
    ) -> Self {
        GuestInput {
            program,
            input_value,
            oracle_tape,
            config,
            tool_names,
            policy_canonical: Vec::new(),
        }
    }

    /// Attach the policy whose `canonical_bytes()` these are.
    pub fn with_policy_canonical(mut self, canonical: Vec<u8>) -> Self {
        self.policy_canonical = canonical;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compiler::compile, host::tape::TapeEntry, parser::parse};
    use alloc::vec;

    fn guest_input_for(src: &str) -> GuestInput {
        let program = compile(&parse(src).unwrap()).unwrap();
        GuestInput::new(
            program,
            LuaValue::Nil,
            OracleTape::new(),
            VmConfig::default(),
            Vec::new(),
        )
    }

    #[test]
    fn replay_executes_the_program() {
        let (output, _) = guest_input_for("return 1 + 2")
            .replay_public_inputs()
            .unwrap();
        assert_eq!(output.return_value, LuaValue::Integer(3));
    }

    #[test]
    fn replay_is_deterministic() {
        let input = guest_input_for("local t = 0 for i = 1, 10 do t = t + i end return t");
        let (out_a, pi_a) = input.replay_public_inputs().unwrap();
        let (out_b, pi_b) = input.replay_public_inputs().unwrap();
        assert_eq!(out_a.return_value, LuaValue::Integer(55));
        assert_eq!(out_a.return_value, out_b.return_value);
        assert_eq!(pi_a, pi_b);
    }

    /// The proof must bind the bytecode that ran, not a hash the prover supplied.
    /// `proveno-compiler` stores a Poseidon2 `program_hash` on `CompiledProgram`;
    /// if that field leaked into the public inputs, a prover could assert any
    /// program hash for any execution.
    #[test]
    fn program_hash_is_recomputed_not_read_from_input() {
        let honest = guest_input_for("return 7");
        let (_, honest_pi) = honest.replay_public_inputs().unwrap();

        let mut tampered = guest_input_for("return 7");
        tampered.program.program_hash = [0xAA; 32];
        let (_, tampered_pi) = tampered.replay_public_inputs().unwrap();

        assert_eq!(honest_pi.program_hash, tampered_pi.program_hash);
        assert_ne!(honest_pi.program_hash, [0xAA; 32]);
        assert_eq!(honest_pi.digest_sha256(), tampered_pi.digest_sha256());
    }

    // ── Policy binding ───────────────────────────────────────────────────────

    #[test]
    fn no_policy_gives_a_zero_policy_hash() {
        let (_, pi) = guest_input_for("return 1").replay_public_inputs().unwrap();
        assert_eq!(pi.policy_hash, [0u8; 32]);
    }

    /// The whole point of shipping canonical bytes rather than a hash: what the
    /// guest commits must equal what `OraclePolicy::policy_hash` produces on
    /// the host, or the two sides disagree about which policy was in force.
    #[cfg(feature = "std")]
    #[test]
    fn guest_policy_hash_matches_oracle_policy_hash() {
        let policy = crate::policy::profiles::constrained_http_v1();
        let input = guest_input_for("return 1").with_policy_canonical(policy.canonical_bytes());

        let (_, pi) = input.replay_public_inputs().unwrap();
        assert_eq!(pi.policy_hash, policy.policy_hash());
        assert_ne!(pi.policy_hash, [0u8; 32]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn different_policies_give_different_digests() {
        let a = crate::policy::profiles::constrained_http_v1();
        let b = crate::policy::profiles::template_price_feed_v1();

        let (_, pa) = guest_input_for("return 1")
            .with_policy_canonical(a.canonical_bytes())
            .replay_public_inputs()
            .unwrap();
        let (_, pb) = guest_input_for("return 1")
            .with_policy_canonical(b.canonical_bytes())
            .replay_public_inputs()
            .unwrap();

        assert_ne!(pa.policy_hash, pb.policy_hash);
        assert_ne!(pa.digest_sha256(), pb.digest_sha256());
    }

    /// A prover editing the policy bytes cannot keep the old hash, because the
    /// guest derives the hash from the bytes rather than accepting one.
    #[cfg(feature = "std")]
    #[test]
    fn tampering_policy_bytes_changes_the_committed_hash() {
        let policy = crate::policy::profiles::constrained_http_v1();
        let honest = policy.canonical_bytes();
        let mut tampered = honest.clone();
        *tampered.last_mut().unwrap() ^= 1;

        let (_, pa) = guest_input_for("return 1")
            .with_policy_canonical(honest)
            .replay_public_inputs()
            .unwrap();
        let (_, pb) = guest_input_for("return 1")
            .with_policy_canonical(tampered)
            .replay_public_inputs()
            .unwrap();
        assert_ne!(pa.policy_hash, pb.policy_hash);
    }

    #[test]
    fn different_programs_get_different_program_hashes() {
        let (_, a) = guest_input_for("return 1").replay_public_inputs().unwrap();
        let (_, b) = guest_input_for("return 2").replay_public_inputs().unwrap();
        assert_ne!(a.program_hash, b.program_hash);
        assert_ne!(a.digest_sha256(), b.digest_sha256());
    }

    /// Same program, different recorded tool responses, must not collide: the
    /// tape is what the proof attests the program consumed.
    #[test]
    fn tape_contents_reach_the_public_inputs() {
        let src = "local r = tool.call(\"t\", {}) return 0";
        let mut a = guest_input_for(src);
        a.oracle_tape = OracleTape {
            entries: vec![TapeEntry::Ok(b"{\"v\":1}".to_vec())],
            attestations: vec![Vec::new()],
        };
        let mut b = guest_input_for(src);
        b.oracle_tape = OracleTape {
            entries: vec![TapeEntry::Ok(b"{\"v\":2}".to_vec())],
            attestations: vec![Vec::new()],
        };

        let (_, pi_a) = a.replay_public_inputs().unwrap();
        let (_, pi_b) = b.replay_public_inputs().unwrap();
        assert_ne!(pi_a.tool_responses_hash, pi_b.tool_responses_hash);
        assert_ne!(pi_a.digest_sha256(), pi_b.digest_sha256());
    }

    /// A tape shorter than the program's tool calls must fail rather than
    /// silently produce a proof over a truncated run.
    #[test]
    fn exhausted_tape_fails_replay() {
        let input = guest_input_for("local r = tool.call(\"t\", {}) return 0");
        assert!(input.replay_public_inputs().is_err());
    }
}
