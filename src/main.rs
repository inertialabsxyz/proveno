use luai::{
    bytecode, compiler,
    host::transcript::ToolCallStatus,
    parser,
    types::{
        table::{LuaKey, LuaTable},
        value::{LuaString, LuaValue},
    },
    vm::{
        engine::{HostInterface, Vm, VmConfig},
        gas::VmError,
    },
};
use std::{
    env, fs,
    io::{self, Read},
};

// ── DemoHost ──────────────────────────────────────────────────────────────────
// A simple host used by example scripts that need real tool responses.
// Supports a small fixed set of tools; all others return an error.

struct DemoHost;

impl HostInterface for DemoHost {
    fn call_tool(&mut self, name: &str, args: &LuaTable) -> Result<LuaTable, String> {
        let mut resp = LuaTable::new();
        let str_key = |s: &str| LuaKey::String(LuaString::from_str(s));
        match name {
            // echo: returns {message = args.message}
            "echo" => {
                let msg = args
                    .get(&str_key("message"))
                    .cloned()
                    .unwrap_or(LuaValue::Nil);
                resp.rawset(str_key("message"), msg).unwrap();
            }
            // add: returns {result = args.a + args.b}
            "add" => {
                let a = match args.get(&str_key("a")) {
                    Some(LuaValue::Integer(n)) => *n,
                    _ => return Err("add: expected integer arg 'a'".into()),
                };
                let b = match args.get(&str_key("b")) {
                    Some(LuaValue::Integer(n)) => *n,
                    _ => return Err("add: expected integer arg 'b'".into()),
                };
                resp.rawset(str_key("result"), LuaValue::Integer(a + b))
                    .unwrap();
            }
            // upper: returns {result = string.upper(args.text)}
            "upper" => {
                let text = match args.get(&str_key("text")) {
                    Some(LuaValue::String(s)) => {
                        String::from_utf8_lossy(s.as_bytes()).to_uppercase()
                    }
                    _ => return Err("upper: expected string arg 'text'".into()),
                };
                resp.rawset(
                    str_key("result"),
                    LuaValue::String(LuaString::from_str(&text)),
                )
                .unwrap();
            }
            // fail: always errors
            "fail" => return Err("this tool always fails".into()),
            other => return Err(format!("unknown tool '{other}'")),
        }
        Ok(resp)
    }
}

fn source_line(source: &str, line: u32) -> &str {
    source
        .lines()
        .nth(line.saturating_sub(1) as usize)
        .unwrap_or("")
}

fn run(source: &str) -> Result<(), VmError> {
    let ast = parser::parse(source).map_err(|e| {
        VmError::RuntimeError(LuaValue::String(luai::types::value::LuaString::from_str(
            &format!("parse error: {e:?}"),
        )))
    })?;
    let program = compiler::compile(&ast).map_err(|e| {
        VmError::RuntimeError(LuaValue::String(luai::types::value::LuaString::from_str(
            &format!("compile error: {e:?}"),
        )))
    })?;
    bytecode::verify(&program).map_err(|e| {
        VmError::RuntimeError(LuaValue::String(luai::types::value::LuaString::from_str(
            &format!("verify error: {e:?}"),
        )))
    })?;

    let mut vm = Vm::new(VmConfig::default(), DemoHost);
    let output = vm.execute(&program, LuaValue::Nil)?;

    for msg in &output.logs {
        println!("{msg}");
    }
    if !matches!(output.return_value, LuaValue::Nil) {
        println!("=> {}", output.return_value);
    }
    if !output.transcript.is_empty() {
        eprintln!("[transcript: {} tool call(s)]", output.transcript.len());
        for r in &output.transcript {
            let args = String::from_utf8_lossy(&r.args_canonical);
            let status = match r.status {
                ToolCallStatus::Ok => format!(
                    "ok  resp={} bytes sha256={}",
                    r.response_bytes,
                    &r.response_hash[..12],
                ),
                ToolCallStatus::Error => "err".to_owned(),
            };
            eprintln!(
                "  [{}] {} args={} gas={} {}",
                r.seq, r.tool_name, args, r.gas_charged, status
            );
        }
    }
    eprintln!(
        "[gas: {}, mem: {} bytes]",
        output.gas_used, output.memory_used
    );
    Ok(())
}

fn main() {
    let source = if let Some(path) = env::args().nth(1) {
        fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("error reading {path}: {e}");
            std::process::exit(1);
        })
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).unwrap();
        buf
    };

    if let Err(e) = run(&source) {
        use luai::vm::gas::VmError;
        match e {
            VmError::WithLine(line, inner) => {
                let text = source_line(&source, line).trim();
                eprintln!("runtime error at line {line}: {inner:?}");
                eprintln!("  --> {text}");
            }
            other => eprintln!("runtime error: {other:?}"),
        }
        std::process::exit(1);
    }
}
