use std::{
    env,
    fs::{self, File},
};

use luai::{VmConfig, compiler::CompiledProgram, types::value::LuaValue};

use crate::{host::ProverHost, prover::Prover};

mod host;
mod prover;

fn main() {
    let compiled = if let Some(path) = env::args().nth(1) {
        fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("error reading {path}: {e}");
            std::process::exit(1);
        })
    } else {
        eprintln!("Provide file name of compiled program");
        return;
    };

    let out_path = match env::args().nth(2) {
        Some(p) => p,
        None => String::from("dry_result.json"),
    };

    // Setup prover
    let host = ProverHost {};
    let vm_config = VmConfig::default();

    let prover = Prover::new(
        vm_config,
        host,
        vec!["random".to_string(), "fail".to_string()],
    );
    let program: CompiledProgram = serde_json::from_str(&compiled).unwrap();
    let result = prover.dry_run(&program.into(), LuaValue::Nil, vec![]).unwrap();
    let f = File::create(&out_path).unwrap();
    serde_json::to_writer(f, &result).unwrap();

    println!("File written - {}", out_path);
}
