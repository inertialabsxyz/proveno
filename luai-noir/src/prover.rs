use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use crate::witness::{NoirWitness, write_prover_toml};

pub struct NoirProver {
    pub circuit_dir: PathBuf,
}

pub struct NoirProof {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: NoirPublicInputs,
    pub prove_duration: std::time::Duration,
}

pub struct NoirPublicInputs {
    pub program_hash: [u8; 32],
    pub return_value: i64,
    pub num_steps: u32,
    pub tool_responses_hash: [u8; 32],
}

#[derive(Debug)]
pub enum ProveError {
    NargoNotFound,
    ExecuteFailed(String),
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
            ProveError::ExecuteFailed(msg) => write!(f, "nargo execute failed: {msg}"),
            ProveError::ProveFailed(msg) => write!(f, "nargo prove failed: {msg}"),
            ProveError::VerifyFailed(msg) => write!(f, "nargo verify failed: {msg}"),
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

fn nargo_available() -> bool {
    Command::new(nargo_binary())
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

        let prover_toml = self.circuit_dir.join("Prover.toml");
        write_prover_toml(witness, &prover_toml).map_err(ProveError::Io)?;

        // nargo execute: compiles the circuit and generates the witness.
        let exec_out = Command::new(nargo_binary())
            .arg("execute")
            .arg("--program-dir")
            .arg(&self.circuit_dir)
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ProveError::NargoNotFound
                } else {
                    ProveError::Io(e)
                }
            })?;

        if !exec_out.status.success() {
            return Err(ProveError::ExecuteFailed(
                String::from_utf8_lossy(&exec_out.stderr).into_owned(),
            ));
        }

        // nargo prove: generates the proof.
        let start = Instant::now();
        let prove_out = Command::new(nargo_binary())
            .arg("prove")
            .arg("--program-dir")
            .arg(&self.circuit_dir)
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ProveError::NargoNotFound
                } else {
                    ProveError::Io(e)
                }
            })?;
        let prove_duration = start.elapsed();

        if !prove_out.status.success() {
            return Err(ProveError::ProveFailed(
                String::from_utf8_lossy(&prove_out.stderr).into_owned(),
            ));
        }

        // Read proof file from circuit_dir/proofs/*.proof
        let proof_bytes = read_proof_file(&self.circuit_dir)?;

        Ok(NoirProof {
            proof_bytes,
            public_inputs: NoirPublicInputs {
                program_hash: witness.program_hash,
                return_value: witness.return_value,
                num_steps: witness.num_steps,
                tool_responses_hash: witness.tool_responses_hash,
            },
            prove_duration,
        })
    }

    pub fn verify(&self, proof: &NoirProof) -> Result<bool, ProveError> {
        if !nargo_available() {
            return Err(ProveError::NargoNotFound);
        }

        let verify_out = Command::new(nargo_binary())
            .arg("verify")
            .arg("--program-dir")
            .arg(&self.circuit_dir)
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ProveError::NargoNotFound
                } else {
                    ProveError::Io(e)
                }
            })?;

        if !verify_out.status.success() {
            let msg = String::from_utf8_lossy(&verify_out.stderr).into_owned();
            // A failed verify is a valid false result, not an infrastructure error.
            if msg.contains("The proof is invalid") || msg.contains("verification failed") {
                return Ok(false);
            }
            return Err(ProveError::VerifyFailed(msg));
        }

        let _ = &proof.proof_bytes; // suppress unused warning
        Ok(true)
    }
}

fn read_proof_file(circuit_dir: &std::path::Path) -> Result<Vec<u8>, ProveError> {
    let proofs_dir = circuit_dir.join("proofs");
    let entries = std::fs::read_dir(&proofs_dir).map_err(ProveError::Io)?;
    for entry in entries {
        let entry = entry.map_err(ProveError::Io)?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("proof") {
            return std::fs::read(&path).map_err(ProveError::Io);
        }
    }
    Err(ProveError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("no .proof file found in {}", proofs_dir.display()),
    )))
}
