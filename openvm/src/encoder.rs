use std::env;
use std::error::Error;
use std::{fs, path::PathBuf};

use luai::compiler::CompiledProgram;
use luai::zkvm::dry_run_result::DryRunResult;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct OpenVMInput {
    pub compiled_program: CompiledProgram,
    pub dry_run_result: DryRunResult,
}

fn encode_input_file<T>(value: &T, path: PathBuf) -> Result<(), Box<dyn Error>>
where
    T: serde::Serialize + ?Sized,
{
    let words = openvm::serde::to_vec(value)?;
    let bytes: Vec<u8> = words.into_iter().flat_map(|w| w.to_le_bytes()).collect();
    let hex_bytes = String::from("0x01") + &hex::encode(&bytes);
    let input = serde_json::json!({
        "input": [hex_bytes]
    });
    fs::write(path, serde_json::to_string(&input)?)?;
    Ok(())
}

fn main() {
    if env::args().len() != 3 {
        eprintln!("Required compiled and dry result paths to generate proof");
        return;
    }

    // pass both compiled.json and dry_result.json
    let compiled = if let Some(path) = env::args().nth(1) {
        fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("error reading {path}: {e}");
            std::process::exit(1);
        })
    } else {
        eprintln!("Provide file name of compiled program");
        return;
    };

    let dry_result = if let Some(path) = env::args().nth(2) {
        fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("error reading {path}: {e}");
            std::process::exit(1);
        })
    } else {
        eprintln!("Provide file name of dry result");
        return;
    };

    let compiled_program: CompiledProgram = serde_json::from_str(&compiled).unwrap();
    let dry_run_result: DryRunResult = serde_json::from_str(&dry_result).unwrap();

    let input = OpenVMInput {
        compiled_program,
        dry_run_result,
    };
    encode_input_file(&input, PathBuf::from("/tmp/openvm-1.json")).unwrap();
}
