use std::{fs, path::PathBuf};

use luai::{
    compiler::proto::CompiledProgram,
    host::tape::OracleTape,
    tls::TlsAttestationRecord,
    types::value::LuaValue,
    vm::engine::VmOutput,
    zkvm::commitment::{PublicInputs, compute_public_inputs},
};
use luai_prover::prover::DryRunResult;

/// Paths and public inputs produced by `build_proof_artifacts`.
pub struct ProveArtifacts {
    pub compiled_path: PathBuf,
    pub dry_result_path: PathBuf,
    pub public_inputs: PublicInputs,
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
    })
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
    out.push_str("  Next steps:\n");
    out.push_str(&format!(
        "    cargo run -p luai-noir -- {} {} --prove\n",
        artifacts.compiled_path.display(),
        artifacts.dry_result_path.display(),
    ));

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
        let artifacts = build_proof_artifacts(
            &program,
            &LuaValue::Nil,
            output,
            vec![],
            dir.path().to_str().unwrap(),
        )
        .unwrap();

        let section = format_prove_section(&artifacts);
        assert!(section.contains("ZK Proof Artifacts"));
        assert!(section.contains("Program hash:"));
        assert!(section.contains("Input hash:"));
        assert!(section.contains("Tool responses hash:"));
        assert!(section.contains("Output hash:"));
        assert!(section.contains("compiled.json"));
        assert!(section.contains("dry_result.json"));
        assert!(section.contains("luai-noir"));
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
