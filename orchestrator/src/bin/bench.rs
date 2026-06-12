//! Phase 3 benchmark: proof generation and on-chain submission data.
//!
//! Compiles a simple Lua program that performs a live http_get, executes it
//! under the `template_price_feed_v1` policy, builds a wire-format proof bundle,
//! and prints everything needed for the on-chain submission step.
//!
//! Usage: cargo run -p proveno-orchestrator --bin bench

use std::time::Instant;

use proveno::{
    bytecode, compiler, parser,
    policy::profiles::template_price_feed_v1,
    types::{
        table::{LuaKey, LuaTable},
        value::{LuaString, LuaValue},
    },
    vm::engine::{HostInterface, VmConfig},
};
use proveno_prover::prover::Prover;
use proveno_verifier::build_test_proof;

/// Minimal host for the benchmark: supports `http_get` only.
struct BenchHost {
    client: reqwest::blocking::Client,
}

impl BenchHost {
    fn new() -> Self {
        BenchHost {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
        }
    }
}

fn str_key(s: &str) -> LuaKey {
    LuaKey::String(LuaString::from_str(s))
}

/// Format a reqwest error including its full source chain.
///
/// reqwest::Error's Display only surfaces the top-line message; the
/// actual cause (TLS / connect / timeout details) lives in `source()`
/// and is lost by a plain `{e}`. This walks the chain and joins each
/// layer with ": ".
fn format_reqwest_error(prefix: &str, e: &reqwest::Error) -> String {
    let mut msg = format!("{prefix}: {e}");
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(e);
    while let Some(cause) = src {
        msg.push_str(": ");
        msg.push_str(&cause.to_string());
        src = cause.source();
    }
    msg
}

impl HostInterface for BenchHost {
    fn call_tool(&mut self, name: &str, args: &LuaTable) -> Result<LuaTable, String> {
        match name {
            "http_get" => {
                let url = match args.get(&str_key("url")) {
                    Some(LuaValue::String(s)) => String::from_utf8_lossy(s.as_bytes()).into_owned(),
                    _ => return Err("http_get: missing 'url' arg".into()),
                };

                let resp = self
                    .client
                    .get(&url)
                    .send()
                    .map_err(|e| format_reqwest_error("http_get failed", &e))?;
                let status = resp.status().as_u16() as i64;
                let body = resp
                    .text()
                    .map_err(|e| format_reqwest_error("http_get: read error", &e))?;

                let mut t = LuaTable::new();
                t.rawset(str_key("status"), LuaValue::Integer(status))
                    .unwrap();
                t.rawset(
                    str_key("body"),
                    LuaValue::String(LuaString::from_str(&body)),
                )
                .unwrap();
                Ok(t)
            }
            other => Err(format!("unknown tool '{other}'")),
        }
    }
}

fn hex32(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    // A simple Lua program that fetches JSON from a public endpoint.
    // Returns the HTTP status code as proof that a real call was made.
    let lua_source = r#"
local r = tool.call("http_get", {url = "https://httpbin.org/json"})
return r.status
"#;

    let policy = template_price_feed_v1();

    eprintln!("=== proveno Phase 3 Benchmark ===");
    eprintln!("Policy: template_price_feed_v1");
    eprintln!("Policy hash: 0x{}", hex32(&policy.policy_hash()));

    // Compile
    eprintln!("\n[1/4] Compiling Lua program...");
    let ast = parser::parse(lua_source).expect("parse failed");
    let program = compiler::compile(&ast).expect("compile failed");
    bytecode::verify(&program).expect("bytecode verify failed");

    // Execute with live HTTP + policy enforcement, compute public inputs
    eprintln!("[2/4] Executing with live HTTP call to httpbin.org...");
    let t0 = Instant::now();
    let prover = Prover::new(VmConfig::default(), BenchHost::new(), vec![]);
    let dry_run_result = prover
        .dry_run_with_policy(&program.into(), LuaValue::Nil, vec![], &policy)
        .expect("dry run failed");
    let exec_ms = t0.elapsed().as_millis();
    eprintln!(
        "      Done in {}ms — return={:?}, tool_calls={}",
        exec_ms,
        dry_run_result.output.return_value,
        dry_run_result.output.transcript.len()
    );

    // Public inputs are already computed inside dry_run_with_policy
    eprintln!("[3/4] Computing public inputs...");
    let public_inputs = dry_run_result.public_inputs;

    // Build wire-format proof bundle (placeholder inner proof blob)
    eprintln!("[4/4] Building wire-format proof bundle...");
    let inner_blob = b"openvm-proof-placeholder";
    let proof_bundle = build_test_proof(&public_inputs, inner_blob);
    let proof_size = proof_bundle.len();

    // Write proof bundle to file
    std::fs::write("bench_proof.bin", &proof_bundle).expect("failed to write bench_proof.bin");

    // Emit machine-readable JSON for the benchmark script
    let pi_json = serde_json::json!({
        "policy_hash":          format!("0x{}", hex32(&public_inputs.policy_hash)),
        "program_hash":         format!("0x{}", hex32(&public_inputs.program_hash)),
        "input_hash":           format!("0x{}", hex32(&public_inputs.input_hash)),
        "tool_responses_hash":  format!("0x{}", hex32(&public_inputs.tool_responses_hash)),
        "output_hash":          format!("0x{}", hex32(&public_inputs.output_hash)),
        "attestation_hash": format!("0x{}", hex32(&public_inputs.attestation_hash)),
        "proof_size_bytes":     proof_size,
        "exec_latency_ms":      exec_ms,
        "proof_bundle_file":    "bench_proof.bin",
        // Tuple string for `cast send "verify(bytes,(...))"`
        "pi_cast_tuple": format!(
            "(0x{},0x{},0x{},0x{},0x{},0x{})",
            hex32(&public_inputs.program_hash),
            hex32(&public_inputs.input_hash),
            hex32(&public_inputs.tool_responses_hash),
            hex32(&public_inputs.output_hash),
            hex32(&public_inputs.attestation_hash),
            hex32(&public_inputs.policy_hash),
        ),
    });

    println!("{}", serde_json::to_string_pretty(&pi_json).unwrap());
}
