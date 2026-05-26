use std::{
    fs,
    path::{Path, PathBuf},
};

use luai::{
    compiler::proto::CompiledProgram,
    host::tape::OracleTape,
    tls::TlsAttestationRecord,
    types::value::LuaValue,
    vm::engine::VmOutput,
    zkvm::commitment::{PublicInputs, compute_public_inputs},
};
use luai_noir::{ProveOptions, ProveOutputError, prove_from_artifacts};
use luai_prover::prover::DryRunResult;

/// Paths and public inputs produced by `build_proof_artifacts`.
pub struct ProveArtifacts {
    pub compiled_path: PathBuf,
    pub dry_result_path: PathBuf,
    pub public_inputs: PublicInputs,
    pub noir_proof: Option<NoirProveSummary>,
}

/// In-memory summary of a Noir proof generated alongside the JSON artifacts.
pub struct NoirProveSummary {
    pub proof_bytes: Vec<u8>,
    /// 8-element `bytes32[]` in circuit-declaration order:
    /// `[num_steps, program_hash, return_value, tool_responses_hash,
    ///   input_hash, output_hash, tls_attestation_hash, policy_hash]`.
    /// Each element is a 0x-prefixed 32-byte hex string.
    pub public_inputs_hex: Vec<String>,
    pub prove_duration_ms: u128,
    pub verified: bool,
}

/// Build ZK proof artifacts from a completed execution.
///
/// Constructs the oracle tape and public inputs from the VM output (post-hoc
/// witness generation), then serializes `compiled.json` and `dry_result.json`
/// into the output directory.
///
/// `tls_attestations` should contain any TLS certificate records captured
/// during HTTP(S) tool calls.  Pass an empty slice when TLS attestation is
/// not available.
pub fn build_proof_artifacts(
    program: &CompiledProgram,
    input: &LuaValue,
    output: VmOutput,
    tls_attestations: Vec<TlsAttestationRecord>,
    output_dir: &str,
) -> Result<ProveArtifacts, String> {
    // Build oracle tape from transcript
    let oracle_tape = OracleTape::from_records(&output.transcript);

    // Compute public inputs (commitment hashes including TLS attestation)
    let public_inputs = compute_public_inputs(
        program.program_hash,
        input,
        &oracle_tape,
        &output,
        &tls_attestations,
    );

    // Assemble DryRunResult
    let dry_run_result = DryRunResult {
        output,
        oracle_tape,
        tls_attestations,
        public_inputs: public_inputs.clone(),
    };

    // Create output directory
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create output directory: {e}"))?;

    // Serialize compiled program
    let compiled_path = PathBuf::from(output_dir).join("compiled.json");
    let compiled_json = serde_json::to_string_pretty(program)
        .map_err(|e| format!("failed to serialize compiled program: {e}"))?;
    fs::write(&compiled_path, &compiled_json)
        .map_err(|e| format!("failed to write {}: {e}", compiled_path.display()))?;

    // Serialize dry run result
    let dry_result_path = PathBuf::from(output_dir).join("dry_result.json");
    let dry_result_json = serde_json::to_string_pretty(&dry_run_result)
        .map_err(|e| format!("failed to serialize dry run result: {e}"))?;
    fs::write(&dry_result_path, &dry_result_json)
        .map_err(|e| format!("failed to write {}: {e}", dry_result_path.display()))?;

    Ok(ProveArtifacts {
        compiled_path,
        dry_result_path,
        public_inputs,
        noir_proof: None,
    })
}

/// Same as `build_proof_artifacts`, but additionally invokes the Noir prover
/// over the produced artifacts and populates `noir_proof`.
///
/// `circuit_dir` must point at the Noir circuit (the directory containing
/// `Nargo.toml`). On a successful proof, `noir_proof` carries the proof bytes,
/// the canonical 8-element `bytes32[]` public inputs, prove duration, and a
/// verify flag. Verification is always attempted.
pub fn build_proof_artifacts_with_noir(
    program: &CompiledProgram,
    input: &LuaValue,
    output: VmOutput,
    tls_attestations: Vec<TlsAttestationRecord>,
    output_dir: &str,
    circuit_dir: &Path,
) -> Result<ProveArtifacts, String> {
    let mut artifacts =
        build_proof_artifacts(program, input, output, tls_attestations, output_dir)?;

    // Reconstruct the `DryRunResult` from the freshly written JSON so we
    // share the exact bytes the standalone luai-noir CLI would consume.
    let dry_json = fs::read_to_string(&artifacts.dry_result_path).map_err(|e| {
        format!(
            "failed to read {}: {e}",
            artifacts.dry_result_path.display()
        )
    })?;
    let dry_run_result: DryRunResult = serde_json::from_str(&dry_json)
        .map_err(|e| format!("failed to parse dry_result.json: {e}"))?;

    let opts = ProveOptions {
        circuit_dir: circuit_dir.to_path_buf(),
        do_verify: true,
    };

    match prove_from_artifacts(program, &dry_run_result, &opts) {
        Ok(out) => {
            let pi = &artifacts.public_inputs;
            let public_inputs_hex = vec![
                u32_to_bytes32_hex(out.witness.num_steps),
                bytes32_hex(&pi.program_hash),
                i64_to_bytes32_hex(out.witness.return_value),
                bytes32_hex(&pi.tool_responses_hash),
                bytes32_hex(&pi.input_hash),
                bytes32_hex(&pi.output_hash),
                bytes32_hex(&pi.tls_attestation_hash),
                bytes32_hex(&pi.policy_hash),
            ];
            artifacts.noir_proof = Some(NoirProveSummary {
                proof_bytes: out.proof.proof_bytes,
                public_inputs_hex,
                prove_duration_ms: out.proof.prove_duration.as_millis(),
                verified: out.verified,
            });
            Ok(artifacts)
        }
        Err(e) => Err(format_prove_error(&e)),
    }
}

fn format_prove_error(e: &ProveOutputError) -> String {
    format!("noir proof generation failed: {e}")
}

/// 0x-prefixed 32-byte hex of `bytes`.
fn bytes32_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(2 + 64);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `u32` left-padded to 32 bytes big-endian.
fn u32_to_bytes32_hex(v: u32) -> String {
    let mut buf = [0u8; 32];
    buf[28..].copy_from_slice(&v.to_be_bytes());
    bytes32_hex(&buf)
}

/// `i64` sign-extended (two's complement) to 32 bytes big-endian.
fn i64_to_bytes32_hex(v: i64) -> String {
    let fill = if v < 0 { 0xFFu8 } else { 0x00u8 };
    let mut buf = [fill; 32];
    buf[24..].copy_from_slice(&v.to_be_bytes());
    bytes32_hex(&buf)
}

fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Format the ZK proof artifacts section for the text report.
pub fn format_prove_section(artifacts: &ProveArtifacts) -> String {
    let pi = &artifacts.public_inputs;
    let mut out = String::new();

    out.push_str("── ZK Proof Artifacts ─────────────────────────\n");
    out.push_str(&format!(
        "  Program hash:        {}\n",
        hex(&pi.program_hash)
    ));
    out.push_str(&format!("  Input hash:          {}\n", hex(&pi.input_hash)));
    out.push_str(&format!(
        "  Tool responses hash: {}\n",
        hex(&pi.tool_responses_hash)
    ));
    out.push_str(&format!(
        "  Output hash:         {}\n",
        hex(&pi.output_hash)
    ));
    out.push('\n');
    out.push_str(&format!(
        "  Compiled program: {}\n",
        artifacts.compiled_path.display()
    ));
    out.push_str(&format!(
        "  Dry run result:   {}\n",
        artifacts.dry_result_path.display()
    ));
    out.push('\n');

    match &artifacts.noir_proof {
        Some(np) => {
            out.push_str("── Noir Proof ─────────────────────────────────\n");
            out.push_str(&format!(
                "  Proof bytes:    {} bytes\n",
                np.proof_bytes.len()
            ));
            out.push_str(&format!(
                "  Prove duration: {:.2}s\n",
                np.prove_duration_ms as f64 / 1000.0
            ));
            out.push_str(&format!(
                "  Verified:       {}\n",
                if np.verified { "yes" } else { "no" }
            ));
            out.push('\n');
            out.push_str("  Public inputs (bytes32[8], canonical order):\n");
            const LABELS: [&str; 8] = [
                "num_steps           ",
                "program_hash        ",
                "return_value        ",
                "tool_responses_hash ",
                "input_hash          ",
                "output_hash         ",
                "tls_attestation_hash",
                "policy_hash         ",
            ];
            for (label, hexstr) in LABELS.iter().zip(np.public_inputs_hex.iter()) {
                out.push_str(&format!("    [{label}] {hexstr}\n"));
            }
            out.push('\n');
            out.push_str("  Submit on-chain (example):\n");
            out.push_str("    cast send <VERIFIER_ADDRESS> 'submit(bytes,bytes32[])' \\\n");
            out.push_str("      <proof-hex> \\\n");
            out.push_str("      \"[");
            for (i, hexstr) in np.public_inputs_hex.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(hexstr);
            }
            out.push_str("]\"\n");
        }
        None => {
            out.push_str("  Next steps:\n");
            out.push_str(&format!(
                "    cargo run -p luai-noir -- {} {} --prove\n",
                artifacts.compiled_path.display(),
                artifacts.dry_result_path.display(),
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline;
    use crate::tools::StubHost;
    use luai::{types::value::LuaValue, vm::engine::VmConfig};

    fn run_program(source: &str) -> (CompiledProgram, VmOutput) {
        let program = pipeline::compile_and_verify(source).unwrap();
        let output =
            pipeline::execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        (program, output)
    }

    #[test]
    fn simple_program_produces_valid_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();

        let (program, output) = run_program("return 42");
        let artifacts =
            build_proof_artifacts(&program, &LuaValue::Nil, output, vec![], dir_str).unwrap();

        // Files exist and are valid JSON
        assert!(artifacts.compiled_path.exists());
        assert!(artifacts.dry_result_path.exists());

        let compiled_json = fs::read_to_string(&artifacts.compiled_path).unwrap();
        let _: CompiledProgram = serde_json::from_str(&compiled_json).unwrap();

        let dry_json = fs::read_to_string(&artifacts.dry_result_path).unwrap();
        let _: DryRunResult = serde_json::from_str(&dry_json).unwrap();
    }

    #[test]
    fn with_tool_calls_has_oracle_entries() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();

        let source = r#"
local r1 = tool.call("echo", {message = "hi"})
local r2 = tool.call("add", {a = 1, b = 2})
return r1.message
"#;
        let (program, output) = run_program(source);
        let artifacts =
            build_proof_artifacts(&program, &LuaValue::Nil, output, vec![], dir_str).unwrap();

        // Deserialize and check oracle tape
        let dry_json = fs::read_to_string(&artifacts.dry_result_path).unwrap();
        let dry: DryRunResult = serde_json::from_str(&dry_json).unwrap();
        assert_eq!(dry.oracle_tape.len(), 2);
    }

    #[test]
    fn tool_calls_change_responses_hash() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();

        let (p1, o1) = run_program("return 1");
        let a1 = build_proof_artifacts(
            &p1,
            &LuaValue::Nil,
            o1,
            vec![],
            dir1.path().to_str().unwrap(),
        )
        .unwrap();

        let source = r#"tool.call("echo", {message = "hi"})
return 1"#;
        let (p2, o2) = run_program(source);
        let a2 = build_proof_artifacts(
            &p2,
            &LuaValue::Nil,
            o2,
            vec![],
            dir2.path().to_str().unwrap(),
        )
        .unwrap();

        assert_ne!(
            a1.public_inputs.tool_responses_hash,
            a2.public_inputs.tool_responses_hash
        );
    }

    #[test]
    fn format_section_contains_all_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let (program, output) = run_program("return 42");
        let mut artifacts = build_proof_artifacts(
            &program,
            &LuaValue::Nil,
            output,
            vec![],
            dir.path().to_str().unwrap(),
        )
        .unwrap();

        // Inject a synthetic Noir proof summary so the format helper renders
        // the proof block without invoking nargo/bb.
        artifacts.noir_proof = Some(NoirProveSummary {
            proof_bytes: vec![0xAA; 128],
            public_inputs_hex: vec![
                u32_to_bytes32_hex(7),
                bytes32_hex(&artifacts.public_inputs.program_hash),
                i64_to_bytes32_hex(42),
                bytes32_hex(&artifacts.public_inputs.tool_responses_hash),
                bytes32_hex(&artifacts.public_inputs.input_hash),
                bytes32_hex(&artifacts.public_inputs.output_hash),
                bytes32_hex(&artifacts.public_inputs.tls_attestation_hash),
                bytes32_hex(&artifacts.public_inputs.policy_hash),
            ],
            prove_duration_ms: 1234,
            verified: true,
        });

        let section = format_prove_section(&artifacts);
        assert!(section.contains("ZK Proof Artifacts"));
        assert!(section.contains("Program hash:"));
        assert!(section.contains("Input hash:"));
        assert!(section.contains("Tool responses hash:"));
        assert!(section.contains("Output hash:"));
        assert!(section.contains("compiled.json"));
        assert!(section.contains("dry_result.json"));
        assert!(section.contains("Proof bytes:"));
        assert!(section.contains("Verified:"));
        assert!(section.contains("cast send"));
    }

    #[test]
    fn bytes32_helpers_pad_correctly() {
        assert_eq!(
            u32_to_bytes32_hex(0),
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            u32_to_bytes32_hex(1),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            i64_to_bytes32_hex(42),
            "0x000000000000000000000000000000000000000000000000000000000000002a"
        );
        // -1 sign-extends to all-FF.
        assert_eq!(
            i64_to_bytes32_hex(-1),
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        // -2 → ...fffffffe.
        assert_eq!(
            i64_to_bytes32_hex(-2),
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
        );
    }

    /// Exercises the full Noir proving path through the orchestrator helper.
    /// Requires `nargo` and `bb` on `PATH`; gated behind the
    /// `noir-prove` feature so default CI runs skip it.
    #[test]
    #[cfg_attr(not(feature = "noir-prove"), ignore)]
    fn build_proof_artifacts_with_noir_produces_verified_proof() {
        let dir = tempfile::tempdir().unwrap();
        let circuit_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../noir");

        let (program, output) = run_program("return 1 + 2");
        let artifacts = build_proof_artifacts_with_noir(
            &program,
            &LuaValue::Nil,
            output,
            vec![],
            dir.path().to_str().unwrap(),
            &circuit_dir,
        )
        .expect("build_proof_artifacts_with_noir failed");

        let np = artifacts
            .noir_proof
            .expect("noir_proof should be populated");
        assert!(np.verified, "proof should verify");
        assert_eq!(np.public_inputs_hex.len(), 8);
        assert!(!np.proof_bytes.is_empty());
    }

    #[test]
    fn public_inputs_match_prover_dry_run() {
        use luai_prover::prover::Prover;

        let source = r#"local r = tool.call("echo", {message = "test"})
return r.message"#;
        let program = pipeline::compile_and_verify(source).unwrap();

        // Path 1: orchestrator post-hoc (no TLS attestations)
        let output =
            pipeline::execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        let oracle_tape = OracleTape::from_records(&output.transcript);
        let pi_orchestrator = compute_public_inputs(
            program.program_hash,
            &LuaValue::Nil,
            &oracle_tape,
            &output,
            &[],
        );

        // Path 2: prover dry_run (no TLS attestations)
        let prover = Prover::new(VmConfig::default(), StubHost, vec!["echo".into()]);
        let dry = prover.dry_run(&program, LuaValue::Nil, vec![]).unwrap();
        let pi_prover = dry.public_inputs;

        assert_eq!(pi_orchestrator, pi_prover);
    }
}
