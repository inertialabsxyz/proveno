use std::{env, fs, path::PathBuf};

use luai::{
    OracleTape, TapeHost, Vm, VmConfig, compiler::CompiledProgram, noir::encoder::encode_program,
    types::value::LuaValue,
};
use luai_noir::{NoirProver, build_witness, write_prover_toml};
use luai_prover::prover::DryRunResult;

fn main() {
    let mut args = env::args().skip(1);

    let compiled_path = args.next().unwrap_or_else(|| {
        eprintln!(
            "usage: luai-noir-witness <compiled.json> <dry_result.json> [--circuit-dir <dir>] [--prove]"
        );
        std::process::exit(1);
    });
    let dry_path = args.next().unwrap_or_else(|| {
        eprintln!(
            "usage: luai-noir-witness <compiled.json> <dry_result.json> [--circuit-dir <dir>] [--prove]"
        );
        std::process::exit(1);
    });

    let mut circuit_dir = PathBuf::from("noir");
    let mut do_prove = false;

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

    let bytecode = encode_program(&compiled_program).unwrap_or_else(|e| {
        eprintln!("encode error: {e:?}");
        std::process::exit(1);
    });

    // Extract fields before consuming dry_run_result.
    let policy_hash = dry_run_result.public_inputs.policy_hash;
    let tls_attestations = dry_run_result.tls_attestations;

    // Re-execute against the oracle tape to record the instruction trace.
    let config = VmConfig {
        record_trace: true,
        ..VmConfig::default()
    };
    let output = Vm::new(config, TapeHost::new(dry_run_result.oracle_tape))
        .execute(&compiled_program, LuaValue::Nil)
        .unwrap_or_else(|e| {
            eprintln!("execution error: {e:?}");
            std::process::exit(1);
        });

    let return_val = match &output.return_value {
        LuaValue::Integer(n) => *n,
        _ => 0,
    };
    let replay_tape = OracleTape::from_records(&output.transcript);

    let witness = build_witness(
        &bytecode,
        &output.trace,
        return_val,
        &replay_tape,
        &LuaValue::Nil,
        &output,
        &tls_attestations,
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

    if do_prove {
        let prover = NoirProver {
            circuit_dir: circuit_dir.clone(),
        };
        let proof = prover.prove(&witness).unwrap_or_else(|e| {
            eprintln!("prove error: {e}");
            std::process::exit(1);
        });
        println!(
            "Proof generated in {:.1}s ({} bytes)",
            proof.prove_duration.as_secs_f64(),
            proof.proof_bytes.len()
        );
        let valid = prover.verify(&proof).unwrap_or_else(|e| {
            eprintln!("verify error: {e}");
            std::process::exit(1);
        });
        if valid {
            println!("Proof verified.");
        } else {
            eprintln!("Proof verification failed.");
            std::process::exit(1);
        }
    }
}
