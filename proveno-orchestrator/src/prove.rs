use std::{
    fs,
    path::{Path, PathBuf},
};

use proveno::{
    compiler::proto::CompiledProgram,
    host::tape::OracleTape,
    types::value::LuaValue,
    vm::engine::VmOutput,
    zkvm::commitment::{PublicInputs, compute_public_inputs},
};
use proveno_noir::{ProveOptions, ProveOutputError, prove_from_artifacts};
use proveno_witness::prover::DryRunResult;

/// Paths and public inputs produced by `build_proof_artifacts`.
pub struct ProveArtifacts {
    /// The Lua source the proof is about.
    ///
    /// Written alongside the other artifacts because a proof of a program you
    /// no longer have is not much use: `compiled.json` holds bytecode, not
    /// something a human can read or recompile from.
    pub source_path: PathBuf,
    pub compiled_path: PathBuf,
    pub dry_result_path: PathBuf,
    pub public_inputs: PublicInputs,
    pub noir_proof: Option<NoirProveSummary>,
    pub openvm_proof: Option<OpenVmProveSummary>,
}

/// Summary of an OpenVM proof generated alongside the JSON artifacts.
pub struct OpenVmProveSummary {
    /// `app` or `stark`.
    pub level: String,
    pub proof_path: PathBuf,
    /// The 32-byte journal digest the guest reveals, hex-encoded.
    pub digest: String,
    pub prove_duration_ms: u128,
    pub verified: bool,
}

/// In-memory summary of a Noir proof generated alongside the JSON artifacts.
pub struct NoirProveSummary {
    pub proof_bytes: Vec<u8>,
    /// 8-element `bytes32[]` in circuit-declaration order:
    /// `[num_steps, program_hash, return_value, tool_responses_hash,
    ///   input_hash, output_hash, attestation_hash, policy_hash]`.
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
/// `attestations` should contain any provenance blobs captured
/// during HTTP(S) tool calls.  Pass an empty slice when TLS attestation is
/// not available.
pub fn build_proof_artifacts(
    program: &CompiledProgram,
    source: &str,
    input: &LuaValue,
    output: VmOutput,
    attestations: Vec<Vec<u8>>,
    output_dir: &str,
) -> Result<ProveArtifacts, String> {
    // Build oracle tape from transcript
    let oracle_tape = OracleTape::from_records(&output.transcript);

    // Compute public inputs (commitment hashes, incl. bind-only attestation)
    let public_inputs = compute_public_inputs(program.program_hash, input, &oracle_tape, &output);

    // Assemble DryRunResult
    let dry_run_result = DryRunResult {
        output,
        oracle_tape,
        attestations,
        public_inputs: public_inputs.clone(),
    };

    // Create output directory
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create output directory: {e}"))?;

    // The generated program itself. For an LLM-authored task this is the only
    // human-readable record of what was proven.
    let source_path = PathBuf::from(output_dir).join("program.lua");
    fs::write(&source_path, source)
        .map_err(|e| format!("failed to write {}: {e}", source_path.display()))?;

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
        source_path,
        compiled_path,
        dry_result_path,
        public_inputs,
        noir_proof: None,
        openvm_proof: None,
    })
}

/// Resolve how to invoke `proveno-openvm-host`.
///
/// Prefers the binary sitting next to the current executable, which is where
/// cargo puts workspace siblings. Falls back to `cargo run` only if that is
/// missing. The preference matters: a nested `cargo run` contends for the
/// target-directory lock, so calling this from a test under `cargo test` can
/// block until the outer command finishes.
fn openvm_host_command(args: Vec<String>) -> (String, Vec<String>) {
    const BIN: &str = "proveno-openvm-host";
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join(BIN);
        if sibling.is_file() {
            return (sibling.display().to_string(), args);
        }
        // Integration tests live in target/<profile>/deps/, one level down.
        if let Some(parent) = dir.parent() {
            let sibling = parent.join(BIN);
            if sibling.is_file() {
                return (sibling.display().to_string(), args);
            }
        }
    }
    let mut fallback = vec![
        "run".into(),
        "-q".into(),
        "-p".into(),
        BIN.into(),
        "--".into(),
    ];
    fallback.extend(args);
    ("cargo".into(), fallback)
}

/// Backend-specific options for [`build_proof_artifacts_with_openvm`].
///
/// Grouped rather than passed positionally: with the source added this was
/// eight arguments, four of them strings, which is easy to transpose at a call
/// site and impossible to catch by type.
pub struct OpenVmOptions<'a> {
    pub output_dir: &'a str,
    /// `app` or `stark`.
    pub level: &'a str,
    /// Must be the policy the execution actually ran under.
    pub policy_spec: Option<&'a str>,
}

/// Same as `build_proof_artifacts`, but proves with the OpenVM backend.
///
/// Shells out to `proveno-openvm-host` over the artifacts just written, the
/// same way the Noir path drives `nargo`/`bb`. That keeps one implementation of
/// the guest-input encoding and the prove/verify dance rather than a second
/// copy here.
///
/// `policy_spec` must be the same policy the execution ran under, or the proof
/// commits to a policy the program was not actually constrained by.
pub fn build_proof_artifacts_with_openvm(
    program: &CompiledProgram,
    source: &str,
    input: &LuaValue,
    output: VmOutput,
    attestations: Vec<Vec<u8>>,
    opts: OpenVmOptions<'_>,
) -> Result<ProveArtifacts, String> {
    let OpenVmOptions {
        output_dir,
        level,
        policy_spec,
    } = opts;
    let mut artifacts =
        build_proof_artifacts(program, source, input, output, attestations, output_dir)?;

    let proof_path = PathBuf::from(output_dir).join(format!("openvm.{level}.proof"));
    let input_path = PathBuf::from(output_dir).join("openvm_input.json");

    let mut args: Vec<String> = vec![
        artifacts.compiled_path.display().to_string(),
        artifacts.dry_result_path.display().to_string(),
        "--out".into(),
        input_path.display().to_string(),
        "--proof".into(),
        proof_path.display().to_string(),
        "--prove".into(),
    ];
    if level == "stark" {
        args.push("--stark".into());
    }
    if let Some(spec) = policy_spec {
        args.push("--policy".into());
        args.push(spec.into());
    }

    let (program_bin, args) = openvm_host_command(args);
    let started = std::time::Instant::now();
    let out = std::process::Command::new(&program_bin)
        .args(&args)
        .output()
        .map_err(|e| format!("failed to run {program_bin}: {e}"))?;
    let elapsed = started.elapsed().as_millis();

    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        return Err(format!(
            "openvm proving failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let digest = stdout
        .lines()
        .find_map(|l| l.strip_prefix("Revealed digest: "))
        .unwrap_or("")
        .trim()
        .to_string();

    // `build_proof_artifacts` fills `public_inputs` with the Poseidon2 scheme
    // the Noir path uses. Those are not what this proof commits: the OpenVM
    // guest uses SHA-256 throughout and derives `policy_hash` itself. Leaving
    // the Poseidon2 values in place made the report print `policy_hash` as zero
    // and "(no policy attached)" for a proof that had in fact bound the policy.
    let dry_json = fs::read_to_string(&artifacts.dry_result_path).map_err(|e| {
        format!(
            "failed to read {}: {e}",
            artifacts.dry_result_path.display()
        )
    })?;
    let dry: DryRunResult = serde_json::from_str(&dry_json)
        .map_err(|e| format!("failed to parse dry_result.json: {e}"))?;

    let mut guest_input = proveno::zkvm::guest_input::GuestInput::new(
        serde_json::from_str(
            &fs::read_to_string(&artifacts.compiled_path)
                .map_err(|e| format!("failed to read compiled.json: {e}"))?,
        )
        .map_err(|e| format!("failed to parse compiled.json: {e}"))?,
        input.clone(),
        dry.oracle_tape.clone(),
        proveno::vm::engine::VmConfig::default(),
        Vec::new(),
    );
    if let Some(spec) = policy_spec {
        let policy = proveno::policy::OraclePolicy::load_spec(spec)?;
        guest_input = guest_input.with_policy_canonical(policy.canonical_bytes());
    }
    match guest_input.replay_public_inputs() {
        Ok((_, pi)) => artifacts.public_inputs = pi,
        Err(e) => return Err(format!("recomputing OpenVM public inputs: {e:?}")),
    }

    artifacts.openvm_proof = Some(OpenVmProveSummary {
        level: level.to_string(),
        proof_path,
        digest,
        prove_duration_ms: elapsed,
        verified: stdout.contains("generated and verified"),
    });
    Ok(artifacts)
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
    source: &str,
    input: &LuaValue,
    output: VmOutput,
    attestations: Vec<Vec<u8>>,
    output_dir: &str,
    circuit_dir: &Path,
) -> Result<ProveArtifacts, String> {
    let mut artifacts =
        build_proof_artifacts(program, source, input, output, attestations, output_dir)?;

    // Reconstruct the `DryRunResult` from the freshly written JSON so we
    // share the exact bytes the standalone proveno-noir CLI would consume.
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
                bytes32_hex(&pi.attestation_hash),
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
    out.push_str(&format!(
        "  Attestation hash:    {}\n",
        hex(&pi.attestation_hash)
    ));
    out.push_str(&format!(
        "  Policy hash:         {}{}\n",
        hex(&pi.policy_hash),
        if pi.policy_hash == [0u8; 32] {
            "  (no policy attached)"
        } else {
            ""
        }
    ));
    out.push('\n');
    out.push_str(&format!(
        "  Program source:   {}\n",
        artifacts.source_path.display()
    ));
    out.push_str(&format!(
        "  Compiled program: {}\n",
        artifacts.compiled_path.display()
    ));
    out.push_str(&format!(
        "  Dry run result:   {}\n",
        artifacts.dry_result_path.display()
    ));
    out.push('\n');

    if let Some(ov) = &artifacts.openvm_proof {
        out.push_str("── OpenVM Proof ───────────────────────────────\n");
        out.push_str(&format!("  Level:           {}\n", ov.level));
        out.push_str(&format!("  Proof:           {}\n", ov.proof_path.display()));
        out.push_str(&format!(
            "  Prove duration:  {:.2}s\n",
            ov.prove_duration_ms as f64 / 1000.0
        ));
        out.push_str(&format!(
            "  Verified:        {}\n",
            if ov.verified { "yes" } else { "no" }
        ));
        out.push_str(&format!("  Journal digest:  {}\n", ov.digest));
        out.push_str(
            "\n  The guest reveals the digest above, a SHA-256 over all six\n\
             \x20 public inputs. A verifier recomputes it from those values.\n",
        );
        return out;
    }

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
                "attestation_hash",
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
                "    cargo run -p proveno-noir -- {} {} --prove\n",
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
    use proveno::{types::value::LuaValue, vm::engine::VmConfig};

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
        let artifacts = build_proof_artifacts(
            &program,
            "return 42",
            &LuaValue::Nil,
            output,
            vec![],
            dir_str,
        )
        .unwrap();

        // The generated source is written verbatim next to the artifacts. A
        // proof of a program nobody kept a copy of is of limited use.
        assert!(artifacts.source_path.exists());
        assert_eq!(
            std::fs::read_to_string(&artifacts.source_path).unwrap(),
            "return 42"
        );
        assert_eq!(artifacts.source_path.file_name().unwrap(), "program.lua");

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
        let artifacts = build_proof_artifacts(
            &program,
            "return 42",
            &LuaValue::Nil,
            output,
            vec![],
            dir_str,
        )
        .unwrap();

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
            "return 1",
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
            source,
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
            "src",
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
                bytes32_hex(&artifacts.public_inputs.attestation_hash),
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

    /// Exercises the full Noir proving path through the proveno-orchestrator helper.
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
            "return 1 + 2",
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
        use proveno_witness::prover::Prover;

        let source = r#"local r = tool.call("echo", {message = "test"})
return r.message"#;
        let program = pipeline::compile_and_verify(source).unwrap();

        // Path 1: proveno-orchestrator post-hoc (no TLS attestations)
        let output =
            pipeline::execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        let oracle_tape = OracleTape::from_records(&output.transcript);
        let pi_orchestrator =
            compute_public_inputs(program.program_hash, &LuaValue::Nil, &oracle_tape, &output);

        // Path 2: prover dry_run (no TLS attestations)
        let prover = Prover::new(VmConfig::default(), StubHost);
        let dry = prover.dry_run(&program, LuaValue::Nil, vec![]).unwrap();
        let pi_prover = dry.public_inputs;

        assert_eq!(pi_orchestrator, pi_prover);
    }
}
