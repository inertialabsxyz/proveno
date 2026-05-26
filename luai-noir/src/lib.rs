pub mod prover;
pub mod witness;

use std::path::PathBuf;

use luai::{
    OracleTape, TapeHost, Vm, VmConfig, compiler::CompiledProgram, noir::encoder::encode_program,
    types::value::LuaValue,
};
use luai_prover::prover::DryRunResult;

pub use prover::{NoirProof, NoirProver, NoirPublicInputs, ProveError};
pub use witness::{NoirWitness, WitnessError, build_witness, write_prover_toml};

/// Options controlling `prove_from_artifacts`.
pub struct ProveOptions {
    /// Directory containing `Nargo.toml` (the Noir circuit).
    pub circuit_dir: PathBuf,
    /// When true, also run `bb verify` and populate `verified`.
    pub do_verify: bool,
}

/// Output of `prove_from_artifacts`: the generated proof, the witness used to
/// produce it, and whether verification succeeded (always `false` when
/// `do_verify` was `false`).
pub struct ProveOutput {
    pub proof: NoirProof,
    pub witness: Box<NoirWitness>,
    pub verified: bool,
}

/// High-level entry point: from a compiled program plus a recorded dry-run
/// result, replay against the oracle tape, build the witness, write
/// `Prover.toml`, invoke `bb prove`, and optionally `bb verify`.
///
/// This mirrors the flow of the `luai-noir` standalone binary so callers can
/// produce in-memory proof artifacts without shelling out.
pub fn prove_from_artifacts(
    compiled: &CompiledProgram,
    dry_result: &DryRunResult,
    opts: &ProveOptions,
) -> Result<ProveOutput, ProveOutputError> {
    let bytecode =
        encode_program(compiled).map_err(|e| ProveOutputError::Encode(format!("{e:?}")))?;

    let policy_hash = dry_result.public_inputs.policy_hash;
    let tls_attestations = dry_result.tls_attestations.clone();
    let oracle_tape = dry_result.oracle_tape.clone();

    // Re-execute against the oracle tape to record the instruction trace.
    let config = VmConfig {
        record_trace: true,
        ..VmConfig::default()
    };
    let output = Vm::new(config, TapeHost::new(oracle_tape))
        .execute(compiled, LuaValue::Nil)
        .map_err(|e| ProveOutputError::Execute(format!("{e:?}")))?;

    let return_val = match &output.return_value {
        LuaValue::Integer(n) => *n,
        _ => 0,
    };
    let replay_tape = OracleTape::from_records(&output.transcript);

    let witness = build_witness(
        &bytecode,
        &output.trace,
        return_val,
        &replay_tape,
        &LuaValue::Nil,
        &output,
        &tls_attestations,
        policy_hash,
    )
    .map_err(ProveOutputError::Witness)?;

    let prover_toml = opts.circuit_dir.join("Prover.toml");
    write_prover_toml(&witness, &prover_toml).map_err(ProveOutputError::Io)?;

    let prover = NoirProver {
        circuit_dir: opts.circuit_dir.clone(),
    };
    let proof = prover.prove(&witness).map_err(ProveOutputError::Prove)?;

    let verified = if opts.do_verify {
        prover.verify(&proof).map_err(ProveOutputError::Prove)?
    } else {
        false
    };

    Ok(ProveOutput {
        proof,
        witness,
        verified,
    })
}

#[derive(Debug)]
pub enum ProveOutputError {
    Encode(String),
    Execute(String),
    Witness(WitnessError),
    Io(std::io::Error),
    Prove(ProveError),
}

impl std::fmt::Display for ProveOutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProveOutputError::Encode(msg) => write!(f, "encode error: {msg}"),
            ProveOutputError::Execute(msg) => write!(f, "execution error: {msg}"),
            ProveOutputError::Witness(e) => write!(f, "witness error: {e}"),
            ProveOutputError::Io(e) => write!(f, "I/O error: {e}"),
            ProveOutputError::Prove(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProveOutputError {}
