//! Chain layer for Phase 4 — submit a `ProvenoVerifier.verify` view call on every
//! generated proof and surface the result to the SSE stream.
//!
//! ## Env vars
//!
//! - **Mode A (default, "managed-anvil")** — no env vars required.
//!   `anvil` and `forge` must be on `PATH`. The server spawns an `anvil`
//!   subprocess on startup, runs `forge script contracts/script/Deploy.s.sol`
//!   against it, parses the `HonkVerifier` / `ProvenoVerifier` addresses out of
//!   the deploy log, and reuses them for every `POST /run`.
//! - **Mode B ("external")** — selected by setting `RPC_URL`.
//!   - `RPC_URL`              (required)
//!   - `PROVENO_VERIFIER_ADDR`   (required)
//!   - `CHAIN_ID`             (optional, default 11155111 = Sepolia)
//!   - `EXPLORER_BASE`        (optional, default `https://sepolia.etherscan.io`)
//!
//! The presence of `RPC_URL` is the mode selector — there is no boolean flag.

use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::Duration;

use alloy::primitives::{Address, Bytes, FixedBytes, B256};
use alloy::providers::ProviderBuilder;
use alloy::sol;
use tokio::time::sleep;

use crate::public_inputs::PublicInputs;

const ANVIL_DEV_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_CHAIN_ID: u64 = 31337;
const ANVIL_PORT: u16 = 38545;

// Generated stubs for the on-chain `ProvenoVerifier.verify(bytes, PublicInputs)`
// view call. The tuple layout must match `~/devel/proveno/contracts/src/Types.sol`
// exactly — reordering fields silently produces wrong-shaped calldata.
sol! {
    #[sol(rpc)]
    contract ProvenoVerifier {
        struct SolPublicInputs {
            uint32  numSteps;
            bytes32 programHash;
            int64   returnValue;
            bytes32 toolResponsesHash;
            bytes32 inputHash;
            bytes32 outputHash;
            bytes32 attestationHash;
            bytes32 policyHash;
        }

        error PolicyHashMismatch();
        error ProofInvalid();

        function verify(bytes calldata proof, SolPublicInputs calldata inputs)
            external view returns (bool);
    }
}

#[derive(Clone, Debug)]
pub struct ChainConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub verifier_addr: Address,
    pub explorer_base: Option<String>,
}

#[derive(Debug)]
pub enum VerifyResult {
    Accepted,
    /// `reason` is one of `"PolicyHashMismatch"`, `"ProofInvalid"`, or `"unknown"`.
    Rejected {
        reason: String,
    },
}

#[derive(Debug)]
pub enum ChainError {
    Io(String),
    Rpc(String),
    Deploy(String),
    Config(String),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::Io(s) => write!(f, "chain io error: {s}"),
            ChainError::Rpc(s) => write!(f, "chain rpc error: {s}"),
            ChainError::Deploy(s) => write!(f, "chain deploy error: {s}"),
            ChainError::Config(s) => write!(f, "chain config error: {s}"),
        }
    }
}

impl std::error::Error for ChainError {}

/// Owns a spawned `anvil` child and kills it on drop so a server crash doesn't
/// leave a stray node listening.
#[derive(Debug)]
pub struct AnvilHandle {
    child: Option<Child>,
}

impl AnvilHandle {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }
}

impl Drop for AnvilHandle {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Resolve a `ChainConfig` from the environment.
///
/// - `RPC_URL` set ⇒ Mode B: no deployment; use provided addresses.
/// - `RPC_URL` unset ⇒ Mode A: spawn `anvil`, deploy contracts, return both.
pub async fn init_chain() -> Result<(ChainConfig, Option<AnvilHandle>), ChainError> {
    match std::env::var("RPC_URL") {
        Ok(rpc_url) if !rpc_url.is_empty() => init_external(rpc_url).await,
        _ => init_managed_anvil().await,
    }
}

fn init_external_sync(rpc_url: String) -> Result<(ChainConfig, Option<AnvilHandle>), ChainError> {
    let verifier_addr = std::env::var("PROVENO_VERIFIER_ADDR")
        .map_err(|_| {
            ChainError::Config("PROVENO_VERIFIER_ADDR must be set when RPC_URL is set".into())
        })?
        .parse::<Address>()
        .map_err(|e| ChainError::Config(format!("invalid PROVENO_VERIFIER_ADDR: {e}")))?;

    let chain_id = match std::env::var("CHAIN_ID") {
        Ok(s) => s
            .parse::<u64>()
            .map_err(|e| ChainError::Config(format!("invalid CHAIN_ID: {e}")))?,
        Err(_) => 11_155_111, // Sepolia
    };

    let explorer_base = match std::env::var("EXPLORER_BASE") {
        Ok(s) if !s.is_empty() => Some(s),
        _ => Some("https://sepolia.etherscan.io".to_string()),
    };

    Ok((
        ChainConfig {
            rpc_url,
            chain_id,
            verifier_addr,
            explorer_base,
        },
        None,
    ))
}

async fn init_external(rpc_url: String) -> Result<(ChainConfig, Option<AnvilHandle>), ChainError> {
    init_external_sync(rpc_url)
}

async fn init_managed_anvil() -> Result<(ChainConfig, Option<AnvilHandle>), ChainError> {
    let proveno_root = locate_proveno_root()?;
    let policy_hash = current_policy_hash()?;

    let rpc_url = format!("http://127.0.0.1:{ANVIL_PORT}");

    // Boot anvil. --code-size-limit 65536 mirrors the CLI demo. The bb 5.0.0
    // HonkVerifier is ~24.0 KB (23,977 B), under the default EIP-170 24576-byte
    // ceiling, so the raised limit is headroom, not a requirement.
    let child = std::process::Command::new("anvil")
        .args([
            "--port",
            &ANVIL_PORT.to_string(),
            "--code-size-limit",
            "65536",
            "--silent",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| ChainError::Io(format!("failed to spawn anvil: {e}")))?;

    let handle = AnvilHandle::new(child);

    // Wait until anvil responds.
    wait_for_anvil(&rpc_url).await?;

    let verifier_addr = deploy_contracts(&proveno_root, &rpc_url, &policy_hash)?;

    Ok((
        ChainConfig {
            rpc_url,
            chain_id: ANVIL_CHAIN_ID,
            verifier_addr,
            explorer_base: None,
        },
        Some(handle),
    ))
}

async fn wait_for_anvil(rpc_url: &str) -> Result<(), ChainError> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_blockNumber",
        "params": [],
        "id": 1,
    });
    for _ in 0..100 {
        if let Ok(resp) = client.post(rpc_url).json(&body).send().await {
            if resp.status().is_success() {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(ChainError::Io(
        "anvil did not become responsive within 10s".into(),
    ))
}

/// Resolve the proveno workspace root. `proveno-demo` lives inside the proveno
/// workspace, so the root (which holds `contracts/`) is the crate's parent dir.
fn locate_proveno_root() -> Result<PathBuf, ChainError> {
    // Cargo manifest dir lets us resolve the workspace root regardless of CWD.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let candidate = PathBuf::from(manifest_dir).join("..");
    if candidate.join("contracts/script/Deploy.s.sol").exists() {
        Ok(candidate
            .canonicalize()
            .map_err(|e| ChainError::Config(format!("canonicalize proveno root: {e}")))?)
    } else {
        Err(ChainError::Config(format!(
            "expected proveno workspace root at {} (Deploy.s.sol not found)",
            candidate.display()
        )))
    }
}

/// Read the current policy hash that the orchestrator's prove pipeline commits
/// to. Phase 2 stubs `policy_hash` as all-zeros (see
/// `proveno::zkvm::commitment::compute_public_inputs`), so the deployed
/// `expectedPolicyHash` must also be zero for `ProvenoVerifier.verify` to pass.
fn current_policy_hash() -> Result<String, ChainError> {
    // Matches `[0u8; 32]` written by `compute_public_inputs` until a real
    // policy commitment is wired through in a later phase.
    Ok("0x0000000000000000000000000000000000000000000000000000000000000000".to_string())
}

fn deploy_contracts(
    proveno_root: &Path,
    rpc_url: &str,
    policy_hash: &str,
) -> Result<Address, ChainError> {
    let output = std::process::Command::new("forge")
        .args([
            "script",
            "contracts/script/Deploy.s.sol",
            "--root",
            "contracts",
            "--rpc-url",
            rpc_url,
            "--private-key",
            ANVIL_DEV_KEY,
            "--broadcast",
            "--disable-code-size-limit",
        ])
        .env("POLICY_HASH", policy_hash)
        .current_dir(proveno_root)
        .output()
        .map_err(|e| ChainError::Io(format!("failed to invoke forge: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(ChainError::Deploy(format!(
            "forge script failed:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_address(&stdout, "ProvenoVerifier:").ok_or_else(|| {
        ChainError::Deploy(format!(
            "could not parse ProvenoVerifier address from forge output:\n{stdout}"
        ))
    })
}

fn parse_address(haystack: &str, marker: &str) -> Option<Address> {
    for line in haystack.lines().rev() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(marker) {
            let token = rest.split_whitespace().next_back()?;
            if let Ok(addr) = token.parse::<Address>() {
                return Some(addr);
            }
        }
    }
    None
}

/// Submit `ProvenoVerifier.verify(proof, inputs)` and translate the result into
/// `VerifyResult`. The custom-error revert selectors are decoded into the
/// `Rejected { reason }` shape the SSE schema exposes.
pub async fn verify_on_chain(
    cfg: &ChainConfig,
    proof: &[u8],
    inputs: &PublicInputs,
) -> Result<VerifyResult, ChainError> {
    let url: alloy::transports::http::reqwest::Url = cfg
        .rpc_url
        .parse()
        .map_err(|e| ChainError::Config(format!("invalid rpc_url: {e}")))?;
    let provider = ProviderBuilder::new().on_http(url);
    let contract = ProvenoVerifier::new(cfg.verifier_addr, provider);

    let sol_inputs = ProvenoVerifier::SolPublicInputs {
        numSteps: inputs.num_steps,
        programHash: FixedBytes::from(inputs.program_hash),
        returnValue: inputs.return_value,
        toolResponsesHash: FixedBytes::from(inputs.tool_responses_hash),
        inputHash: FixedBytes::from(inputs.input_hash),
        outputHash: FixedBytes::from(inputs.output_hash),
        attestationHash: FixedBytes::from(inputs.attestation_hash),
        policyHash: FixedBytes::from(inputs.policy_hash),
    };
    let proof_bytes = Bytes::from(proof.to_vec());

    match contract.verify(proof_bytes, sol_inputs).call().await {
        Ok(ret) => {
            if ret._0 {
                Ok(VerifyResult::Accepted)
            } else {
                Ok(VerifyResult::Rejected {
                    reason: "unknown".into(),
                })
            }
        }
        Err(e) => {
            let reason = classify_revert(&e);
            Ok(VerifyResult::Rejected { reason })
        }
    }
}

fn classify_revert(err: &alloy::contract::Error) -> String {
    let s = format!("{err}");
    // Selectors lifted verbatim from ProvenoVerifier.sol custom-error definitions.
    if s.contains("0xdec0f374") || s.contains("PolicyHashMismatch") {
        "PolicyHashMismatch".into()
    } else if s.contains("0x7fcdd1f4") || s.contains("ProofInvalid") {
        "ProofInvalid".into()
    } else {
        "unknown".into()
    }
}

#[allow(dead_code)]
fn b256(bytes: [u8; 32]) -> B256 {
    B256::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_address_picks_last_marker_line() {
        let log = "\
HonkVerifier: 0x5FbDB2315678afecb367f032d93F642f64180aa3
ProvenoVerifier: 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
ProvenoConsumer: 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
";
        let addr = parse_address(log, "ProvenoVerifier:").unwrap();
        assert_eq!(
            format!("{addr:?}").to_lowercase(),
            "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512"
        );
    }

    #[test]
    fn parse_address_returns_none_when_marker_missing() {
        let log = "no addresses here\n";
        assert!(parse_address(log, "ProvenoVerifier:").is_none());
    }

    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn external_mode_requires_verifier_addr() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("PROVENO_VERIFIER_ADDR");
        }
        let err = init_external_sync("https://example.com".into()).expect_err("should error");
        assert!(matches!(err, ChainError::Config(_)));
    }

    #[test]
    fn external_mode_defaults_to_sepolia() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(
                "PROVENO_VERIFIER_ADDR",
                "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
            );
            std::env::remove_var("CHAIN_ID");
            std::env::remove_var("EXPLORER_BASE");
        }
        let (cfg, handle) = init_external_sync("https://example.com".into()).unwrap();
        assert!(handle.is_none());
        assert_eq!(cfg.chain_id, 11_155_111);
        assert_eq!(
            cfg.explorer_base.as_deref(),
            Some("https://sepolia.etherscan.io")
        );
        unsafe {
            std::env::remove_var("PROVENO_VERIFIER_ADDR");
        }
    }
}
