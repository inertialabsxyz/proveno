use std::{env, fs, path::PathBuf};

use proveno::compiler::CompiledProgram;
use proveno_noir::{ProveOptions, prove_from_artifacts};
use proveno_prover::prover::DryRunResult;

fn main() {
    let mut args = env::args().skip(1);

    let compiled_path = args.next().unwrap_or_else(|| {
        eprintln!(
            "usage: proveno-noir-witness <compiled.json> <dry_result.json> [--circuit-dir <dir>] [--prove]"
        );
        std::process::exit(1);
    });
    let dry_path = args.next().unwrap_or_else(|| {
        eprintln!(
            "usage: proveno-noir-witness <compiled.json> <dry_result.json> [--circuit-dir <dir>] [--prove]"
        );
        std::process::exit(1);
    });

    let mut circuit_dir = PathBuf::from("noir");
    let mut do_prove = false;
    let mut as_json = false;

    loop {
        match args.next().as_deref() {
            None => break,
            Some("--circuit-dir") => {
                circuit_dir = PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("--circuit-dir requires a value");
                    std::process::exit(1);
                }));
            }
            Some("--prove") => do_prove = true,
            // Emit the proof + 8-element bytes32[] public inputs as JSON on
            // stdout (same shape the orchestrator's --json prove path prints),
            // so scripts can feed them to on-chain verification. Implies --prove.
            Some("--json") => {
                as_json = true;
                do_prove = true;
            }
            Some(arg) => {
                eprintln!("unknown argument: {arg}");
                std::process::exit(1);
            }
        }
    }

    let compiled_json = fs::read_to_string(&compiled_path).unwrap_or_else(|e| {
        eprintln!("error reading {compiled_path}: {e}");
        std::process::exit(1);
    });
    let compiled_program: CompiledProgram =
        serde_json::from_str(&compiled_json).unwrap_or_else(|e| {
            eprintln!("error parsing {compiled_path}: {e}");
            std::process::exit(1);
        });

    let dry_json = fs::read_to_string(&dry_path).unwrap_or_else(|e| {
        eprintln!("error reading {dry_path}: {e}");
        std::process::exit(1);
    });
    let dry_run_result: DryRunResult = serde_json::from_str(&dry_json).unwrap_or_else(|e| {
        eprintln!("error parsing {dry_path}: {e}");
        std::process::exit(1);
    });

    if !do_prove {
        // Replicate prior behaviour: write Prover.toml only, no proving.
        use proveno::{
            TapeHost, Vm, VmConfig, noir::encoder::encode_program, types::value::LuaValue,
        };
        use proveno_noir::{build_witness, write_prover_toml};

        let bytecode = encode_program(&compiled_program).unwrap_or_else(|e| {
            eprintln!("encode error: {e:?}");
            std::process::exit(1);
        });
        let policy_hash = dry_run_result.public_inputs.policy_hash;
        let oracle_tape = dry_run_result.oracle_tape.clone();
        let config = VmConfig {
            record_trace: true,
            ..VmConfig::default()
        };
        let output = Vm::new(config, TapeHost::new(oracle_tape))
            .execute(&compiled_program, LuaValue::Nil)
            .unwrap_or_else(|e| {
                eprintln!("execution error: {e:?}");
                std::process::exit(1);
            });
        let return_val = match &output.return_value {
            LuaValue::Integer(n) => *n,
            _ => 0,
        };
        // Witness from the original tape so per-call attestations survive (the
        // replay through TapeHost reproduces responses but not provenance).
        let witness = build_witness(
            &bytecode,
            &output.trace,
            return_val,
            &dry_run_result.oracle_tape,
            &LuaValue::Nil,
            &output,
            policy_hash,
        )
        .unwrap_or_else(|e| {
            eprintln!("witness error: {e}");
            std::process::exit(1);
        });
        let prover_toml = circuit_dir.join("Prover.toml");
        write_prover_toml(&witness, &prover_toml).unwrap_or_else(|e| {
            eprintln!("error writing Prover.toml: {e}");
            std::process::exit(1);
        });
        println!("Prover.toml written → {}", prover_toml.display());
        return;
    }

    let opts = ProveOptions {
        circuit_dir: circuit_dir.clone(),
        do_verify: true,
    };
    let result =
        prove_from_artifacts(&compiled_program, &dry_run_result, &opts).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        });

    if !result.verified {
        eprintln!("Proof verification failed.");
        std::process::exit(1);
    }

    if as_json {
        // Progress notes go to stderr so stdout stays pure JSON.
        eprintln!(
            "Prover.toml written → {}",
            circuit_dir.join("Prover.toml").display()
        );
        eprintln!(
            "Proof generated in {:.1}s ({} bytes); verified",
            result.proof.prove_duration.as_secs_f64(),
            result.proof.proof_bytes.len()
        );
        let w = &result.witness;
        let public_inputs = vec![
            u32_to_bytes32_hex(w.num_steps),
            bytes32_hex(&w.program_hash),
            i64_to_bytes32_hex(w.return_value),
            bytes32_hex(&w.tool_responses_hash),
            bytes32_hex(&w.input_hash),
            bytes32_hex(&w.output_hash),
            bytes32_hex(&w.attestation_hash),
            bytes32_hex(&w.policy_hash),
        ];
        let json = serde_json::json!({
            "return_value": w.return_value,
            "proving": {
                "proof_bytes_hex": bytes_to_0x_hex(&result.proof.proof_bytes),
                "public_inputs": public_inputs,
                "prove_duration_ms": result.proof.prove_duration.as_millis() as u64,
                "verified": result.verified,
            }
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        return;
    }

    println!(
        "Prover.toml written → {}",
        circuit_dir.join("Prover.toml").display()
    );
    println!(
        "Proof generated in {:.1}s ({} bytes)",
        result.proof.prove_duration.as_secs_f64(),
        result.proof.proof_bytes.len()
    );
    println!("Proof verified.");
}

/// 0x-prefixed lowercase hex of an arbitrary byte slice.
fn bytes_to_0x_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 0x-prefixed 32-byte hex of `bytes`.
fn bytes32_hex(bytes: &[u8; 32]) -> String {
    bytes_to_0x_hex(bytes)
}

/// `u32` left-padded to 32 bytes big-endian, as 0x-prefixed hex.
fn u32_to_bytes32_hex(v: u32) -> String {
    let mut buf = [0u8; 32];
    buf[28..].copy_from_slice(&v.to_be_bytes());
    bytes32_hex(&buf)
}

/// `i64` sign-extended (two's complement) to 32 bytes big-endian, as 0x hex.
fn i64_to_bytes32_hex(v: i64) -> String {
    let fill = if v < 0 { 0xFFu8 } else { 0x00u8 };
    let mut buf = [fill; 32];
    buf[24..].copy_from_slice(&v.to_be_bytes());
    bytes32_hex(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_0x_hex_prefixes_and_lowercases() {
        assert_eq!(bytes_to_0x_hex(&[0x00, 0xab, 0xff]), "0x00abff");
        assert_eq!(bytes_to_0x_hex(&[]), "0x");
    }

    #[test]
    fn u32_to_bytes32_hex_left_pads_big_endian() {
        assert_eq!(
            u32_to_bytes32_hex(1),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            u32_to_bytes32_hex(0xdead_beef),
            "0x00000000000000000000000000000000000000000000000000000000deadbeef"
        );
    }

    #[test]
    fn i64_to_bytes32_hex_sign_extends() {
        assert_eq!(
            i64_to_bytes32_hex(42),
            "0x000000000000000000000000000000000000000000000000000000000000002a"
        );
        // -1 sign-extends to all 0xFF.
        assert_eq!(
            i64_to_bytes32_hex(-1),
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        // -2 -> two's complement low 8 bytes 0xff..fe, sign-extended.
        assert_eq!(
            i64_to_bytes32_hex(-2),
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
        );
    }
}
