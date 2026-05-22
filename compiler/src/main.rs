use std::{
    env,
    fs::{self, File},
};

use luai::{bytecode, compiler, parser};

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: luai-compiler <source.lua> [output.json]");
        std::process::exit(1);
    });
    let source = fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("error reading {path}: {e}");
        std::process::exit(1);
    });

    let out_path = match env::args().nth(2) {
        Some(p) => p,
        None => String::from("compiled.json"),
    };

    let ast = match parser::parse(&source) {
        Ok(v) => v,
        Err(e) => {
            eprint!("parse error: {e:?}");
            return;
        }
    };

    let program = match compiler::compile(&ast) {
        Ok(v) => v,
        Err(e) => {
            eprint!("compile error: {e:?}");
            return;
        }
    };

    if let Err(e) = bytecode::verify(&program) {
        eprintln!("verification error: {e:?}");
        return;
    }

    let out_file = File::create(&out_path).unwrap();
    serde_json::to_writer(out_file, &program).unwrap();
    println!("File written - {}", out_path);
}
