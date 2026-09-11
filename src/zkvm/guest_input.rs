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
    zkvm::commitment::{PublicInputs, compute_public_inputs_sha256},
};

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
    /// Not bound: [`VmConfig`]. The prover picks the gas and memory limits,
    /// which decide whether execution completes or aborts. Committing to the
    /// config is follow-on work.
    pub fn replay_public_inputs(&self) -> Result<(VmOutput, PublicInputs), VmError> {
        let program_hash = compute_program_hash_sha256(&self.program.prototypes);
        let mut vm = Vm::new(self.config.clone(), TapeHost::new(self.oracle_tape.clone()));
        let output = vm.execute(&self.program, self.input_value.clone())?;
        let public_inputs = compute_public_inputs_sha256(
            program_hash,
            &self.input_value,
            &self.oracle_tape,
            &output,
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
        }
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
