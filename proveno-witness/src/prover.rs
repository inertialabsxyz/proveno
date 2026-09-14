//! `Prover` — dry-run and proof generation for Lua agent executions.

use proveno::{
    compiler::proto::CompiledProgram,
    host::tape::OracleTape,
    policy::OraclePolicy,
    types::value::LuaValue,
    vm::engine::{HostInterface, Vm, VmConfig},
    zkvm::commitment::{compute_public_inputs, compute_public_inputs_with_policy},
};

pub use proveno::zkvm::dry_run_result::DryRunResult;

/// Executes Lua programs and (optionally) proves executions in the zkVM.
pub struct Prover<H: HostInterface> {
    config: VmConfig,
    host: H,
}

impl<H: HostInterface> Prover<H> {
    /// Create a new prover with the given VM config, live host, and registered tool names.
    pub fn new(config: VmConfig, host: H) -> Self {
        Prover { config, host }
    }

    /// Execute the program with the live host, record a transcript, and build an oracle tape.
    ///
    /// This is "phase 1" of the two-phase execution model. The result contains
    /// the oracle tape needed for the zkVM replay.
    ///
    /// `attestations` is empty when no provenance provider is attached.
    /// Pass attestations collected outside the VM (e.g. from a TLS-aware host
    /// wrapper) via the `attestations` parameter.
    pub fn dry_run(
        self,
        program: &CompiledProgram,
        input: LuaValue,
        attestations: Vec<Vec<u8>>,
    ) -> Result<DryRunResult, proveno::VmError> {
        let mut vm = Vm::new(self.config.clone(), self.host);
        let output = vm.execute(program, input.clone())?;

        let oracle_tape = OracleTape::from_records(&output.transcript);
        let public_inputs =
            compute_public_inputs(program.program_hash, &input, &oracle_tape, &output);

        Ok(DryRunResult {
            output,
            oracle_tape,
            attestations,
            public_inputs,
        })
    }

    /// Execute the program under `policy`, record a transcript, and build an oracle tape.
    ///
    /// Like `dry_run` but enforces the policy during execution and populates
    /// `policy_hash` in the returned `PublicInputs`.
    pub fn dry_run_with_policy(
        self,
        program: &CompiledProgram,
        input: LuaValue,
        attestations: Vec<Vec<u8>>,
        policy: &OraclePolicy,
    ) -> Result<DryRunResult, proveno::VmError> {
        let mut vm = Vm::new(
            self.config.clone(),
            proveno::policy::OraclePolicyHost::new(self.host, policy),
        );
        let output = vm.execute(program, input.clone())?;

        let oracle_tape = OracleTape::from_records(&output.transcript);
        let public_inputs = compute_public_inputs_with_policy(
            program.program_hash,
            &input,
            &oracle_tape,
            &output,
            policy,
        );

        Ok(DryRunResult {
            output,
            oracle_tape,
            attestations,
            public_inputs,
        })
    }

    // /// Build a `GuestInput` from a dry-run result (for passing to the zkVM).
    // pub fn build_guest_input(
    //     &self,
    //     program: CompiledProgram,
    //     input: LuaValue,
    //     dry_run: &DryRunResult,
    // ) -> GuestInput {
    //     GuestInput::new(
    //         program,
    //         input,
    //         dry_run.oracle_tape.clone(),
    //         self.config.clone(),
    //         self._tool_names.clone(),
    //     )
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::ProverHost;
    use proveno::{compiler, parser, policy::profiles::constrained_http_v1};

    #[test]
    fn dry_run_with_policy_sets_policy_hash() {
        let ast = parser::parse("return 42").unwrap();
        let program = compiler::compile(&ast).unwrap();

        let policy = constrained_http_v1();
        let expected_hash = policy.policy_hash();

        let prover = Prover::new(VmConfig::default(), ProverHost::new());
        let result = prover
            .dry_run_with_policy(&program.into(), LuaValue::Nil, vec![], &policy)
            .expect("dry_run_with_policy failed");

        assert_eq!(result.public_inputs.policy_hash, expected_hash);
        assert_ne!(result.public_inputs.policy_hash, [0u8; 32]);
    }
}
