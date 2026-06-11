use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::witness::{NoirWitness, write_prover_toml};

/// Name of the Noir circuit binary as declared in `noir/Nargo.toml`.
/// Nargo writes ACIR + witness artifacts under `<circuit_dir>/target/<CIRCUIT_NAME>.{json,gz}`.
const CIRCUIT_NAME: &str = "trace_verifier";

pub struct NoirProver {
    pub circuit_dir: PathBuf,
}

pub struct NoirProof {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: NoirPublicInputs,
    pub prove_duration: std::time::Duration,
}

/// The six-hash public inputs produced by the Noir proof, matching the
/// `PublicInputs` struct from `src/zkvm/commitment.rs`.
pub struct NoirPublicInputs {
    pub program_hash: [u8; 32],
    pub input_hash: [u8; 32],
    pub tool_responses_hash: [u8; 32],
    pub output_hash: [u8; 32],
    pub tls_attestation_hash: [u8; 32],
    pub policy_hash: [u8; 32],
}

#[derive(Debug)]
pub enum ProveError {
    NargoNotFound,
    BbNotFound,
    ExecuteFailed(String),
    WriteVkFailed(String),
    ProveFailed(String),
    VerifyFailed(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ProveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProveError::NargoNotFound => write!(
                f,
                "nargo not found; install from https://noir-lang.org/docs/getting_started/installation"
            ),
            ProveError::BbNotFound => write!(
                f,
                "bb (Barretenberg) not found; install via `bbup` or from https://github.com/AztecProtocol/aztec-packages"
            ),
            ProveError::ExecuteFailed(msg) => write!(f, "nargo execute failed: {msg}"),
            ProveError::WriteVkFailed(msg) => write!(f, "bb write_vk failed: {msg}"),
            ProveError::ProveFailed(msg) => write!(f, "bb prove failed: {msg}"),
            ProveError::VerifyFailed(msg) => write!(f, "bb verify failed: {msg}"),
            ProveError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ProveError {}

impl From<std::io::Error> for ProveError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::NotFound {
            ProveError::NargoNotFound
        } else {
            ProveError::Io(e)
        }
    }
}

fn nargo_binary() -> &'static str {
    "nargo"
}

fn bb_binary() -> &'static str {
    "bb"
}

fn nargo_available() -> bool {
    Command::new(nargo_binary())
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn bb_available() -> bool {
    Command::new(bb_binary())
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

impl NoirProver {
    pub fn prove(&self, witness: &NoirWitness) -> Result<NoirProof, ProveError> {
        if !nargo_available() {
            return Err(ProveError::NargoNotFound);
        }
        if !bb_available() {
            return Err(ProveError::BbNotFound);
        }

        let prover_toml = self.circuit_dir.join("Prover.toml");
        write_prover_toml(witness, &prover_toml).map_err(ProveError::Io)?;

        // 1. nargo execute → compiles the circuit + solves the witness.
        //    Produces <circuit_dir>/target/<CIRCUIT_NAME>.{json,gz}.
        let exec_out = Command::new(nargo_binary())
            .arg("execute")
            .arg("--program-dir")
            .arg(&self.circuit_dir)
            .output()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ProveError::NargoNotFound,
                _ => ProveError::Io(e),
            })?;

        if !exec_out.status.success() {
            return Err(ProveError::ExecuteFailed(
                String::from_utf8_lossy(&exec_out.stderr).into_owned(),
            ));
        }

        let target_dir = self.circuit_dir.join("target");
        let bytecode_path = target_dir.join(format!("{CIRCUIT_NAME}.json"));
        let witness_path = target_dir.join(format!("{CIRCUIT_NAME}.gz"));
        let vk_path = target_dir.join("vk");
        let proof_path = target_dir.join("proof");

        // 2. bb write_vk → cached on disk; only regenerate if missing or stale
        //    relative to the ACIR bytecode. `-t evm` selects the keccak/ZK
        //    pipeline that matches the on-chain HonkVerifier.sol; without it
        //    bb defaults to a different verifier target and the proof bytes
        //    cannot be verified on chain.
        if vk_needs_refresh(&vk_path, &bytecode_path)? {
            let vk_out = Command::new(bb_binary())
                .arg("write_vk")
                .arg("-b")
                .arg(&bytecode_path)
                .arg("-o")
                .arg(&target_dir)
                .arg("-t")
                .arg("evm")
                .output()
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => ProveError::BbNotFound,
                    _ => ProveError::Io(e),
                })?;
            if !vk_out.status.success() {
                return Err(ProveError::WriteVkFailed(
                    String::from_utf8_lossy(&vk_out.stderr).into_owned(),
                ));
            }
        }

        // 3. bb prove → produces target/proof and target/public_inputs.
        //    `-t evm` must match the target used for write_vk above.
        let start = Instant::now();
        let prove_out = Command::new(bb_binary())
            .arg("prove")
            .arg("-b")
            .arg(&bytecode_path)
            .arg("-w")
            .arg(&witness_path)
            .arg("-k")
            .arg(&vk_path)
            .arg("-o")
            .arg(&target_dir)
            .arg("-t")
            .arg("evm")
            .output()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ProveError::BbNotFound,
                _ => ProveError::Io(e),
            })?;
        let prove_duration = start.elapsed();

        if !prove_out.status.success() {
            return Err(ProveError::ProveFailed(
                String::from_utf8_lossy(&prove_out.stderr).into_owned(),
            ));
        }

        let proof_bytes = std::fs::read(&proof_path).map_err(ProveError::Io)?;

        Ok(NoirProof {
            proof_bytes,
            public_inputs: NoirPublicInputs {
                program_hash: witness.program_hash,
                input_hash: witness.input_hash,
                tool_responses_hash: witness.tool_responses_hash,
                output_hash: witness.output_hash,
                tls_attestation_hash: witness.tls_attestation_hash,
                policy_hash: witness.policy_hash,
            },
            prove_duration,
        })
    }

    pub fn verify(&self, proof: &NoirProof) -> Result<bool, ProveError> {
        if !bb_available() {
            return Err(ProveError::BbNotFound);
        }

        let target_dir = self.circuit_dir.join("target");
        let vk_path = target_dir.join("vk");
        let proof_path = target_dir.join("proof");
        let public_inputs_path = target_dir.join("public_inputs");

        let verify_out = Command::new(bb_binary())
            .arg("verify")
            .arg("-k")
            .arg(&vk_path)
            .arg("-p")
            .arg(&proof_path)
            .arg("-i")
            .arg(&public_inputs_path)
            .arg("-t")
            .arg("evm")
            .output()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ProveError::BbNotFound,
                _ => ProveError::Io(e),
            })?;

        if !verify_out.status.success() {
            let msg = String::from_utf8_lossy(&verify_out.stderr).into_owned();
            // bb signals a failed (but well-formed) verification with a non-zero
            // exit and "verification failed" or "invalid" wording; treat that as
            // a valid `Ok(false)` rather than an infrastructure error.
            if msg.contains("invalid") || msg.contains("verification failed") {
                return Ok(false);
            }
            return Err(ProveError::VerifyFailed(msg));
        }

        let _ = &proof.proof_bytes; // suppress unused warning
        Ok(true)
    }
}

/// True when the verification key on disk should be regenerated — either it's
/// missing or older than the ACIR bytecode it was derived from.
fn vk_needs_refresh(vk_path: &Path, bytecode_path: &Path) -> Result<bool, ProveError> {
    let vk_meta = match std::fs::metadata(vk_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(ProveError::Io(e)),
    };
    let bytecode_meta = std::fs::metadata(bytecode_path).map_err(ProveError::Io)?;
    match (vk_meta.modified(), bytecode_meta.modified()) {
        (Ok(vk_mtime), Ok(bc_mtime)) => Ok(vk_mtime < bc_mtime),
        _ => Ok(true), // mtime unavailable on this fs — regenerate to be safe
    }
}
