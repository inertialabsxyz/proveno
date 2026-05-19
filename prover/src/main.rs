use std::{
    env,
    fs::{self, File},
};

use luai::{VmConfig, compiler::CompiledProgram, policy::OraclePolicy, types::value::LuaValue};

use crate::{host::ProverHost, prover::Prover};

mod host;
mod prover;

fn parse_policy(name: &str) -> Option<OraclePolicy> {
    use luai::policy::profiles::{constrained_http_v1, template_price_feed_v1};
    match name {
        "constrained_http_v1" => Some(constrained_http_v1()),
        "template_price_feed_v1" => Some(template_price_feed_v1()),
        _ => None,
    }
}

fn main() {
    let mut args = env::args().skip(1);

    let compiled = match args.next() {
        Some(path) => fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("error reading {path}: {e}");
            std::process::exit(1);
        }),
        None => {
            eprintln!(
                "Usage: luai-prover <compiled.json> [output.json] [--policy constrained_http_v1|template_price_feed_v1]"
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
    let prover = Prover::new(
        vm_config,
        host,
        vec![
            "http_get".to_string(),
            "random".to_string(),
            "fail".to_string(),
        ],
    );
    let program: CompiledProgram = serde_json::from_str(&compiled).unwrap();

    let result = match policy_name.as_deref() {
        Some(name) => {
            let policy = parse_policy(name).unwrap_or_else(|| {
                eprintln!(
                    "unknown policy '{name}'; valid: constrained_http_v1, template_price_feed_v1"
                );
                std::process::exit(1);
            });
            prover
                .dry_run_with_policy(&program.into(), LuaValue::Nil, vec![], &policy)
                .unwrap()
        }
        None => prover
            .dry_run(&program.into(), LuaValue::Nil, vec![])
            .unwrap(),
    };

    let f = File::create(&out_path).unwrap();
    serde_json::to_writer(f, &result).unwrap();
    println!("File written - {}", out_path);
}
