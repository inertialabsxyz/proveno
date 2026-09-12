use std::{
    env,
    fs::{self, File},
};

use proveno::{VmConfig, compiler::CompiledProgram, policy::OraclePolicy, types::value::LuaValue};

use crate::{host::ProverHost, prover::Prover};

mod host;
mod prover;

fn main() {
    let mut args = env::args().skip(1);

    let compiled = match args.next() {
        Some(path) => fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("error reading {path}: {e}");
            std::process::exit(1);
        }),
        None => {
            eprintln!(
                "Usage: proveno-witness <compiled.json> [output.json] [--policy <profile|file.json>]\n\
         profiles: constrained_http_v1, template_price_feed_v1"
            );
            return;
        }
    };

    let mut out_path = String::from("dry_result.json");
    let mut policy_name: Option<String> = None;

    loop {
        match args.next().as_deref() {
            None => break,
            Some("--policy") => {
                policy_name = args.next();
                if policy_name.is_none() {
                    eprintln!("--policy requires a value");
                    std::process::exit(1);
                }
            }
            Some(arg) => out_path = arg.to_string(),
        }
    }

    let host = ProverHost::new();
    let vm_config = VmConfig::default();
    let prover = Prover::new(vm_config, host);
    let program: CompiledProgram = serde_json::from_str(&compiled).unwrap();

    let result = match policy_name.as_deref() {
        Some(name) => {
            let policy = OraclePolicy::load_spec(name).unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(1);
            });
            eprintln!(
                "policy: {name}  hash={}",
                policy
                    .policy_hash()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            prover.dry_run_with_policy(&program.into(), LuaValue::Nil, vec![], &policy)
        }
        None => prover.dry_run(&program.into(), LuaValue::Nil, vec![]),
    };

    // A policy violation is an expected outcome, not a bug, so report it rather
    // than panicking with a Debug-formatted VmError.
    let result = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: dry run failed: {}", format_vm_error(&e));
            std::process::exit(1);
        }
    };

    let f = File::create(&out_path).unwrap_or_else(|e| {
        eprintln!("error: cannot create {out_path}: {e}");
        std::process::exit(1);
    });
    serde_json::to_writer(f, &result).unwrap_or_else(|e| {
        eprintln!("error: cannot write {out_path}: {e}");
        std::process::exit(1);
    });
    println!("File written - {}", out_path);
}

/// Unwrap the `WithLine` wrapper so a policy rejection reads as the reason it
/// happened rather than as a nested Debug dump.
fn format_vm_error(e: &proveno::VmError) -> String {
    use proveno::VmError;
    match e {
        VmError::WithLine(line, inner) => format!("line {line}: {}", format_vm_error(inner)),
        VmError::RuntimeError(LuaValue::String(s)) => {
            String::from_utf8_lossy(s.as_bytes()).into_owned()
        }
        other => format!("{other:?}"),
    }
}
