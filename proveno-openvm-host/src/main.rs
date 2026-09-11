//! Host-side driver for the OpenVM proving backend.
//!
//! Mirrors what `proveno-noir` does for the Noir backend: takes the artifacts
//! the existing pipeline already produces and turns them into something the
//! prover can consume.
//!
//! ```text
//! proveno-compiler source.lua compiled.json
//! proveno-witness  compiled.json dry_result.json
//! proveno-openvm-host compiled.json dry_result.json --prove
//! ```
//!
//! The guest commits with SHA-256 rather than the Poseidon2 scheme the Noir
//! path uses, so the `public_inputs` already sitting in `dry_result.json` are
//! the wrong scheme for this backend. They are recomputed here.

use std::{env, fs, process::Command};

use proveno::{
    compiler::proto::CompiledProgram,
    host::canonicalize::canonical_serialize,
    types::value::LuaValue,
    vm::engine::VmConfig,
    zkvm::{commitment::PublicInputs, dry_run_result::DryRunResult, guest_input::GuestInput},
};

const USAGE: &str = "\
Usage: proveno-openvm-host <compiled.json> <dry_result.json> [options]

Options:
  --out <path>     where to write the guest input JSON [default: openvm_input.json]
  --prove          generate and verify a proof
  --stark          prove at the aggregated STARK level instead of `app`
  --proof <path>   where to write the proof [default: <level>.proof]
  --help           show this message

Proof levels: `app` is the application STARK; `--stark` recursively aggregates
its segments into a single root STARK. `app` needs `cargo openvm keygen
--app-only`; `--stark` needs `cargo openvm keygen` with no flag (agg_prefix.pk).";

/// Encode a value the way `openvm_sdk::StdIn::write` does, wrapped in the JSON
/// envelope `cargo openvm --input <file>` expects.
///
/// `to_vec` yields u32 words; `StdIn` flattens them little-endian and pushes
/// them as raw bytes. The leading `01` is the CLI's "these are bytes" tag (`02`
/// would mean native field elements). The CLI only accepts a bare hex string on
/// the command line; from a file it wants `{"input": [...]}`.
fn encode_guest_input(input: &GuestInput) -> Result<String, String> {
    let words =
        openvm::serde::to_vec(input).map_err(|e| format!("serializing guest input: {e}"))?;
    let bytes: Vec<u8> = words.into_iter().flat_map(|w| w.to_le_bytes()).collect();
    let hex = format!("01{}", hex::encode(bytes));
    serde_json::to_string(&serde_json::json!({ "input": [hex] }))
        .map_err(|e| format!("building input envelope: {e}"))
}

/// Written by `cargo openvm prove stark`; `verify stark` cannot find it on its
/// own because it guesses the workspace root package name.
const BASELINE: &str = "openvm/release/proveno-openvm.baseline.json";

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn print_public_inputs(pi: &PublicInputs) {
    println!("  program_hash        {}", hex32(&pi.program_hash));
    println!("  input_hash          {}", hex32(&pi.input_hash));
    println!("  tool_responses_hash {}", hex32(&pi.tool_responses_hash));
    println!("  output_hash         {}", hex32(&pi.output_hash));
    println!("  attestation_hash    {}", hex32(&pi.attestation_hash));
    println!("  policy_hash         {}", hex32(&pi.policy_hash));
}

/// Run a `cargo openvm` subcommand, streaming its output.
fn run_openvm(args: &[&str]) -> Result<(), String> {
    println!("\n$ cargo openvm {}", args.join(" "));
    let status = Command::new("cargo")
        .arg("openvm")
        .args(args)
        .status()
        .map_err(|e| format!("running `cargo openvm {}`: {e}", args.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "`cargo openvm {}` failed with {status}",
            args.join(" ")
        ))
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return Ok(());
    }

    let mut positional = Vec::new();
    let mut out_path = String::from("openvm_input.json");
    let mut prove = false;
    let mut stark = false;
    let mut proof_path: Option<String> = None;
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--prove" => prove = true,
            "--stark" => stark = true,
            "--proof" => proof_path = Some(it.next().ok_or("--proof requires a value")?),
            "--out" => out_path = it.next().ok_or("--out requires a value")?,
            other if other.starts_with("--") => {
                return Err(format!("unknown option '{other}'\n\n{USAGE}"))
            }
            other => positional.push(other.to_string()),
        }
    }
    let [compiled_path, dry_result_path] = positional.as_slice() else {
        return Err(format!(
            "expected 2 positional arguments, got {}\n\n{USAGE}",
            positional.len()
        ));
    };

    let compiled =
        fs::read_to_string(compiled_path).map_err(|e| format!("reading {compiled_path}: {e}"))?;
    let program: CompiledProgram =
        serde_json::from_str(&compiled).map_err(|e| format!("parsing {compiled_path}: {e}"))?;

    let dry = fs::read_to_string(dry_result_path)
        .map_err(|e| format!("reading {dry_result_path}: {e}"))?;
    let dry: DryRunResult =
        serde_json::from_str(&dry).map_err(|e| format!("parsing {dry_result_path}: {e}"))?;

    // These must match what proveno-witness used for the dry run, or the guest
    // replay diverges and the proof fails to generate.
    let input_value = LuaValue::Nil;
    let config = VmConfig::default();

    let guest_input = GuestInput::new(
        program,
        input_value,
        dry.oracle_tape.clone(),
        config,
        Vec::new(),
    );

    // Runs the same replay the guest will, via the same function. Doing it here
    // first means a divergence surfaces as a plain error rather than as a proof
    // that silently reveals the wrong digest.
    let (output, expected) = guest_input
        .replay_public_inputs()
        .map_err(|e| format!("host replay failed, so the guest would too: {e:?}"))?;
    let digest = expected.digest_sha256();

    // Compare canonical bytes, not `LuaValue` equality: `LuaValue::Table` uses
    // `Rc::ptr_eq` (correct Lua identity semantics), so two structurally
    // identical tables from separate runs are never `==`. Canonical
    // serialization is also the encoding the commitments hash, which makes it
    // the right notion of "same result" here.
    let canon =
        |v: &LuaValue| canonical_serialize(v).unwrap_or_else(|_| b"<unserializable>".to_vec());
    let (replayed, recorded) = (canon(&output.return_value), canon(&dry.output.return_value));
    if replayed != recorded {
        return Err(format!(
            "replay diverged from the dry run:\n  dry run returned {}\n  replay  returned {}",
            String::from_utf8_lossy(&recorded),
            String::from_utf8_lossy(&replayed)
        ));
    }

    println!(
        "Replayed return value: {}",
        String::from_utf8_lossy(&replayed)
    );
    println!("\nPublic inputs (SHA-256 scheme):");
    print_public_inputs(&expected);
    println!("\nExpected journal digest: {}", hex32(&digest));
    println!("  (this is what the guest reveals as 8 little-endian u32 words)");

    let encoded = encode_guest_input(&guest_input)?;
    fs::write(&out_path, &encoded).map_err(|e| format!("writing {out_path}: {e}"))?;
    println!(
        "\nGuest input written to {out_path} ({} bytes)",
        encoded.len()
    );
    println!("Run it:   cargo openvm run -p proveno-openvm --input {out_path}");

    if prove {
        let level = if stark { "stark" } else { "app" };
        let proof = proof_path.unwrap_or_else(|| format!("proveno-openvm.{level}.proof"));

        run_openvm(&[
            "prove",
            level,
            "-p",
            "proveno-openvm",
            "--input",
            &out_path,
            "--proof",
            &proof,
        ])?;

        // `verify stark` derives the baseline path from the binary target name
        // and guesses the root package, so it looks for proveno.baseline.json
        // and fails. Point it at the real file.
        let mut verify = vec!["verify", level, "--proof", proof.as_str()];
        if stark {
            verify.push("--app-baseline");
            verify.push(BASELINE);
        }
        run_openvm(&verify)?;

        println!("\n{level} proof generated and verified: {proof}");
        println!("Revealed digest: {}", hex32(&digest));
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proveno::{compiler::compile, host::tape::TapeEntry, parser::parse};

    fn guest_input_for(src: &str) -> GuestInput {
        GuestInput::new(
            compile(&parse(src).unwrap()).unwrap(),
            LuaValue::Nil,
            proveno::host::tape::OracleTape::new(),
            VmConfig::default(),
            Vec::new(),
        )
    }

    /// The host/guest boundary: whatever is encoded here must deserialize on the
    /// guest into something that replays identically. OpenVM's serde is a
    /// word-oriented format with no `deserialize_any`, so nested enums, byte
    /// strings and maps surviving it is a real property worth pinning.
    #[test]
    fn guest_input_survives_openvm_serde_round_trip() {
        let original = guest_input_for("local t = 0 for i = 1, 10 do t = t + i end return t");
        let words = openvm::serde::to_vec(&original).unwrap();
        let decoded: GuestInput = openvm::serde::from_slice(&words).unwrap();

        let (out_a, pi_a) = original.replay_public_inputs().unwrap();
        let (out_b, pi_b) = decoded.replay_public_inputs().unwrap();
        assert_eq!(
            out_a.return_value,
            proveno::types::value::LuaValue::Integer(55)
        );
        assert_eq!(out_a.return_value, out_b.return_value);
        assert_eq!(pi_a, pi_b);
        assert_eq!(pi_a.digest_sha256(), pi_b.digest_sha256());
    }

    /// Regression: the divergence check must compare canonical bytes, not
    /// `LuaValue` equality.
    ///
    /// `LuaValue::Table` compares with `Rc::ptr_eq` (correct Lua identity
    /// semantics), so two structurally identical tables built by separate runs
    /// are never `==`. Checking with `!=` rejected every table-returning
    /// program as "diverged" and refused to prove it — which is exactly what
    /// happened to examples/window_max_breach.lua.
    #[test]
    fn table_returning_program_is_not_reported_as_diverged() {
        let input = guest_input_for("local t = {} t.a = 1 t.b = 2 return t");
        let (a, _) = input.replay_public_inputs().unwrap();
        let (b, _) = input.replay_public_inputs().unwrap();

        // The trap: identical tables from two runs compare unequal.
        assert_ne!(
            a.return_value, b.return_value,
            "LuaValue::Table is identity-compared; if this ever changes, the \
             canonical-bytes comparison below is still correct but this test's \
             premise is stale"
        );

        // What the driver actually checks, and what the commitments hash.
        let ca = canonical_serialize(&a.return_value).unwrap();
        let cb = canonical_serialize(&b.return_value).unwrap();
        assert_eq!(ca, cb);
        assert_eq!(String::from_utf8_lossy(&ca), r#"{"a":1,"b":2}"#);
    }

    /// Tapes carry arbitrary response bytes, including non-UTF8, so the encoding
    /// must be byte-transparent rather than string-shaped.
    #[test]
    fn round_trip_preserves_tape_bytes() {
        let mut input = guest_input_for("local r = tool.call(\"t\", {}) return 0");
        input.oracle_tape = proveno::host::tape::OracleTape {
            entries: vec![TapeEntry::Ok(b"{\"v\":\"\\xff\\x00 binary\"}".to_vec())],
            attestations: vec![b"\x00\x01\xfe".to_vec()],
        };
        let words = openvm::serde::to_vec(&input).unwrap();
        let decoded: GuestInput = openvm::serde::from_slice(&words).unwrap();
        assert_eq!(decoded.oracle_tape.entries, input.oracle_tape.entries);
        assert_eq!(
            decoded.oracle_tape.attestations,
            input.oracle_tape.attestations
        );
        assert_eq!(
            decoded.oracle_tape.commitment_hash_sha256(),
            input.oracle_tape.commitment_hash_sha256()
        );
    }

    /// The CLI rejects anything that is not `{"input": ["<hex>"]}` with an
    /// `01`/`02` tag byte, and a malformed envelope only shows up at prove time.
    #[test]
    fn encoded_envelope_has_the_shape_the_cli_expects() {
        let encoded = encode_guest_input(&guest_input_for("return 1")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        let arr = v["input"].as_array().expect("input must be an array");
        assert_eq!(arr.len(), 1);
        let hex_str = arr[0].as_str().unwrap();
        assert!(hex_str.starts_with("01"), "must carry the bytes tag");
        assert!(hex_str.len().is_multiple_of(2), "must be even-length hex");
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
        // Body is whole u32 words, since StdIn flattens to_vec output LE.
        assert!((hex_str.len() - 2).is_multiple_of(8));
    }
}
