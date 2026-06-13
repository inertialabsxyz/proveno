use std::path::PathBuf;
use std::sync::Arc;

use proveno::{types::value::LuaValue, vm::engine::VmConfig};
use proveno_orchestrator::{
    llm::{self, LlmClient, Message},
    pipeline::{self, format_return_value},
    prompt, prove,
    tools::{self, LiveHost},
};
use tokio::sync::mpsc;

use crate::chain::{self, ChainConfig, VerifyResult};
use crate::events::{DemoEvent, ProofHashes};
use crate::public_inputs::PublicInputs;

const GAS_LIMIT: u64 = 1_000_000;
const MAX_TOOL_CALLS: usize = 10;

fn vm_config() -> VmConfig {
    VmConfig {
        gas_limit: GAS_LIMIT,
        max_tool_calls: MAX_TOOL_CALLS,
        ..Default::default()
    }
}

pub fn run_pipeline(task: String, tx: mpsc::Sender<DemoEvent>, chain_config: Arc<ChainConfig>) {
    if let Err(stage) = run_pipeline_inner(task, &tx, chain_config) {
        let _ = tx.blocking_send(DemoEvent::Error {
            message: stage.message,
            at_stage: stage.at_stage.into(),
        });
    }
}

struct StageError {
    message: String,
    at_stage: &'static str,
}

fn send(tx: &mpsc::Sender<DemoEvent>, ev: DemoEvent) -> Result<(), StageError> {
    tx.blocking_send(ev).map_err(|_| StageError {
        message: "client disconnected".into(),
        at_stage: "send",
    })
}

fn run_pipeline_inner(
    task: String,
    tx: &mpsc::Sender<DemoEvent>,
    chain_config: Arc<ChainConfig>,
) -> Result<(), StageError> {
    // ── LLM: generate Lua ────────────────────────────────────────────
    send(
        tx,
        DemoEvent::GeneratingLua {
            prompt: task.clone(),
        },
    )?;

    let api_key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| StageError {
        message: "ANTHROPIC_API_KEY environment variable not set".into(),
        at_stage: "generating_lua",
    })?;
    let model =
        std::env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| "claude-sonnet-4-20250514".into());

    let client = LlmClient::new(llm::Backend::Anthropic { api_key }, model);
    let tool_descs = tools::live_tool_descriptions();
    let system_prompt = prompt::build_system_prompt(&tool_descs);

    let messages = vec![Message {
        role: "user".into(),
        content: task.clone(),
    }];

    let llm_response = client
        .generate(&system_prompt, &messages)
        .map_err(|e| StageError {
            message: format!("LLM generation failed: {e}"),
            at_stage: "generating_lua",
        })?;

    let source = llm::strip_code_fences(&llm_response.text);
    send(
        tx,
        DemoEvent::LuaReady {
            lua: source.clone(),
        },
    )?;

    // ── Compile + verify ─────────────────────────────────────────────
    send(tx, DemoEvent::Compiling)?;
    let program = pipeline::compile_and_verify(&source).map_err(|e| StageError {
        message: e.to_string(),
        at_stage: "compiling",
    })?;

    // ── Execute ──────────────────────────────────────────────────────
    send(tx, DemoEvent::Executing)?;
    let host = LiveHost::new(client.clone());
    let output =
        pipeline::execute(&program, LuaValue::Nil, vm_config(), host).map_err(|e| StageError {
            message: e.to_string(),
            at_stage: "executing",
        })?;

    for record in &output.transcript {
        send(
            tx,
            DemoEvent::ToolCall {
                name: record.tool_name.clone(),
                args: String::from_utf8_lossy(&record.args_canonical).to_string(),
                response: String::from_utf8_lossy(&record.response_canonical).to_string(),
            },
        )?;
    }

    // ── Prove ────────────────────────────────────────────────────────
    send(tx, DemoEvent::Proving)?;

    let return_value_json = format_return_value(&output.return_value);

    let tmp = tempfile::tempdir().map_err(|e| StageError {
        message: format!("failed to create temp dir: {e}"),
        at_stage: "proving",
    })?;
    let dir_str = tmp.path().to_string_lossy().to_string();

    let circuit_dir = locate_circuit_dir().map_err(|e| StageError {
        message: e,
        at_stage: "proving",
    })?;

    let artifacts = prove::build_proof_artifacts_with_noir(
        &program,
        &LuaValue::Nil,
        output,
        vec![],
        &dir_str,
        &circuit_dir,
    )
    .map_err(|e| StageError {
        message: e,
        at_stage: "proving",
    })?;

    let pi = &artifacts.public_inputs;
    let hashes = ProofHashes {
        program_hash: hex32(&pi.program_hash),
        input_hash: hex32(&pi.input_hash),
        tool_responses_hash: hex32(&pi.tool_responses_hash),
        output_hash: hex32(&pi.output_hash),
        attestation_hash: hex32(&pi.attestation_hash),
        policy_hash: hex32(&pi.policy_hash),
    };

    let noir = artifacts.noir_proof.ok_or(StageError {
        message: "noir proof artifact missing".into(),
        at_stage: "proving",
    })?;

    let public_inputs = PublicInputs {
        num_steps: parse_u32_bytes32(&noir.public_inputs_hex[0]).map_err(|e| StageError {
            message: e,
            at_stage: "proving",
        })?,
        program_hash: pi.program_hash,
        return_value: parse_i64_bytes32(&noir.public_inputs_hex[2]).map_err(|e| StageError {
            message: e,
            at_stage: "proving",
        })?,
        tool_responses_hash: pi.tool_responses_hash,
        input_hash: pi.input_hash,
        output_hash: pi.output_hash,
        attestation_hash: pi.attestation_hash,
        policy_hash: pi.policy_hash,
    };
    let proof_bytes = noir.proof_bytes;

    send(
        tx,
        DemoEvent::Complete {
            result: return_value_json,
            hashes,
        },
    )?;

    // ── On-chain verify ─────────────────────────────────────────────
    send(
        tx,
        DemoEvent::VerifyingOnChain {
            chain_id: chain_config.chain_id,
            verifier_addr: format!("{:#x}", chain_config.verifier_addr),
            explorer_base: chain_config.explorer_base.clone(),
        },
    )?;

    // We're inside `spawn_blocking`, so we can't use the ambient runtime's
    // `block_on` directly — building a fresh single-thread runtime is the
    // simplest cross-context way to drive the async alloy call to completion.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| StageError {
            message: format!("failed to build tokio runtime: {e}"),
            at_stage: "verifying_on_chain",
        })?;
    let verify_result = rt
        .block_on(chain::verify_on_chain(
            &chain_config,
            &proof_bytes,
            &public_inputs,
        ))
        .map_err(|e| StageError {
            message: e.to_string(),
            at_stage: "verifying_on_chain",
        })?;

    let (accepted, reason) = match verify_result {
        VerifyResult::Accepted => (true, None),
        VerifyResult::Rejected { reason } => (false, Some(reason)),
    };

    send(
        tx,
        DemoEvent::VerifiedOnChain {
            accepted,
            reason,
            tx_hash: None,
        },
    )?;

    Ok(())
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn parse_bytes32(hex_with_prefix: &str) -> Result<[u8; 32], String> {
    let s = hex_with_prefix
        .strip_prefix("0x")
        .unwrap_or(hex_with_prefix);
    if s.len() != 64 {
        return Err(format!("bytes32 hex must be 64 chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        out[i] = u8::from_str_radix(byte_str, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn parse_u32_bytes32(hex_with_prefix: &str) -> Result<u32, String> {
    let bytes = parse_bytes32(hex_with_prefix)?;
    Ok(u32::from_be_bytes([
        bytes[28], bytes[29], bytes[30], bytes[31],
    ]))
}

fn parse_i64_bytes32(hex_with_prefix: &str) -> Result<i64, String> {
    let bytes = parse_bytes32(hex_with_prefix)?;
    Ok(i64::from_be_bytes([
        bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
    ]))
}

fn locate_circuit_dir() -> Result<PathBuf, String> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let candidate = PathBuf::from(manifest_dir).join("../noir");
    if candidate.join("Nargo.toml").exists() {
        candidate
            .canonicalize()
            .map_err(|e| format!("canonicalize circuit dir: {e}"))
    } else {
        Err(format!(
            "noir circuit directory not found at {} (expected proveno workspace root)",
            candidate.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_u32_bytes32_decodes_canonical_padding() {
        let v =
            parse_u32_bytes32("0x0000000000000000000000000000000000000000000000000000000000000007")
                .unwrap();
        assert_eq!(v, 7);
    }

    #[test]
    fn parse_i64_bytes32_handles_positive() {
        let v =
            parse_i64_bytes32("0x000000000000000000000000000000000000000000000000000000000000002a")
                .unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn parse_i64_bytes32_handles_negative() {
        // Two's-complement -1 packed by `i64_to_bytes32_hex` in the orchestrator.
        let v =
            parse_i64_bytes32("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        assert_eq!(v, -1);
    }

    #[test]
    fn parse_bytes32_rejects_wrong_length() {
        assert!(parse_bytes32("0x00").is_err());
    }
}
