//! End-to-end check of the OpenVM proving backend, without the LLM.
//!
//! `--backend openvm` is only reachable through the orchestrator after a
//! successful LLM generation, so this exercises the proving half directly: take
//! a compiled program and a real execution, then drive
//! `build_proof_artifacts_with_openvm` exactly as the CLI does.
//!
//! Ignored by default. It needs `cargo-openvm` on PATH and proving keys from
//! `cargo openvm keygen --app-only`, and it takes roughly ten seconds:
//!
//!     cargo test -p proveno-orchestrator --test openvm_backend -- --ignored --nocapture

use proveno::{
    policy::OraclePolicy,
    types::value::LuaValue,
    vm::engine::{NoopHost, VmConfig},
};
use proveno_orchestrator::{pipeline, prove};

const POLICY: &str = "constrained_http_v1";

fn run(src: &str, policy: Option<&str>) -> prove::ProveArtifacts {
    let program = pipeline::compile_and_verify(src).expect("compiles");
    let output = pipeline::execute(&program, LuaValue::Nil, VmConfig::default(), NoopHost)
        .expect("executes");
    // Unique per call: these tests can run concurrently and each writes
    // compiled.json / dry_result.json / a proof into its directory.
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "proveno-openvm-backend-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    prove::build_proof_artifacts_with_openvm(
        &program,
        &LuaValue::Nil,
        output,
        vec![],
        dir.to_str().unwrap(),
        "app",
        policy,
    )
    .expect("openvm proving succeeds")
}

#[test]
#[ignore = "needs cargo-openvm and proving keys; ~10s"]
fn openvm_backend_proves_and_verifies() {
    let artifacts = run("return 1 + 2", None);
    let ov = artifacts.openvm_proof.expect("openvm summary present");

    assert_eq!(ov.level, "app");
    assert!(ov.verified, "proof did not verify");
    assert_eq!(ov.digest.len(), 64, "digest should be 32 bytes of hex");
    assert!(ov.proof_path.is_file(), "proof file was not written");
    assert!(artifacts.compiled_path.is_file());
    assert!(artifacts.dry_result_path.is_file());
}

/// The policy the execution ran under must reach the proof. Without this the
/// backend would happily emit a proof whose policy_hash is zero while the CLI
/// reported a policy was in force.
#[test]
#[ignore = "needs cargo-openvm and proving keys; ~10s"]
fn openvm_backend_commits_the_policy_hash() {
    let with = run("return 1 + 2", Some(POLICY));
    let ov = with.openvm_proof.expect("openvm summary present");
    assert!(ov.verified);

    let expected = OraclePolicy::load_spec(POLICY).unwrap().policy_hash();
    let expected_hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();

    // The digest commits policy_hash, so attaching a policy must change it.
    let without = run("return 1 + 2", None);
    let ov_without = without.openvm_proof.expect("openvm summary present");
    assert_ne!(
        ov.digest, ov_without.digest,
        "attaching policy {expected_hex} did not change the journal digest"
    );
}
