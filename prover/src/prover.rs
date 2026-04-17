//! `Prover` — dry-run and proof generation for Lua agent executions.

use luai::{
    compiler::proto::CompiledProgram,
    host::tape::OracleTape,
    tls::TlsAttestationRecord,
    types::value::LuaValue,
    vm::engine::{HostInterface, Vm, VmConfig, VmOutput},
    zkvm::{
        commitment::{PublicInputs, compute_public_inputs},
        guest_input::GuestInput,
    },
};
use serde::{Deserialize, Serialize};

/// Result of a dry run: the VM output, oracle tape, TLS attestations, and
/// the public inputs computed from all of the above.
#[derive(Debug, Serialize, Deserialize)]
pub struct DryRunResult {
    pub output: VmOutput,
    pub oracle_tape: OracleTape,
    /// TLS attestation records captured during HTTP(S) tool calls.
    /// Empty when the host does not make HTTPS calls or does not support
    /// TLS attestation.
    pub tls_attestations: Vec<TlsAttestationRecord>,
    pub public_inputs: PublicInputs,
}

/// Executes Lua programs and (optionally) proves executions in the zkVM.
pub struct Prover<H: HostInterface> {
    config: VmConfig,
    host: H,
    tool_names: Vec<String>,
}

impl<H: HostInterface> Prover<H> {
    /// Create a new prover with the given VM config, live host, and registered tool names.
    pub fn new(config: VmConfig, host: H, tool_names: Vec<String>) -> Self {
        Prover {
            config,
            host,
            tool_names,
        }
    }

    /// Execute the program with the live host, record a transcript, and build an oracle tape.
    ///
    /// This is "phase 1" of the two-phase execution model. The result contains
    /// the oracle tape needed for the zkVM replay.
    ///
    /// `tls_attestations` is empty when the host does not support TLS capture.
    /// Pass attestations collected outside the VM (e.g. from a TLS-aware host
    /// wrapper) via the `tls_attestations` parameter.
    pub fn dry_run(
        self,
        program: &CompiledProgram,
        input: LuaValue,
        tls_attestations: Vec<TlsAttestationRecord>,
    ) -> Result<DryRunResult, luai::VmError> {
        let mut vm = Vm::new(self.config.clone(), self.host);
        let output = vm.execute(program, input.clone())?;

        let oracle_tape = OracleTape::from_records(&output.transcript);
        let public_inputs =
            compute_public_inputs(program.program_hash, &input, &oracle_tape, &output, &tls_attestations);

        Ok(DryRunResult {
            output,
            oracle_tape,
            tls_attestations,
            public_inputs,
        })
    }

    /// Build a `GuestInput` from a dry-run result (for passing to the zkVM).
    pub fn build_guest_input(
        &self,
        program: CompiledProgram,
        input: LuaValue,
        dry_run: &DryRunResult,
    ) -> GuestInput {
        GuestInput::new(
            program,
            input,
            dry_run.oracle_tape.clone(),
            self.config.clone(),
            self.tool_names.clone(),
        )
    }
}
