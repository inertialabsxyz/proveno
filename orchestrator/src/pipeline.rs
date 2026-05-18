use sha2::{Digest, Sha256};

use luai::{
    bytecode,
    compiler::{self, proto::CompiledProgram},
    host::{canonicalize::canonical_serialize, transcript::ToolCallStatus},
    parser,
    types::value::LuaValue,
    vm::{
        engine::{HostInterface, Vm, VmConfig, VmOutput},
        gas::VmError,
    },
};

/// Format a LuaValue as a serde_json::Value for JSON output.
pub fn format_return_value(v: &LuaValue) -> serde_json::Value {
    match v {
        LuaValue::Table(_) => match canonical_serialize(v) {
            Ok(bytes) => {
                let compact = String::from_utf8_lossy(&bytes);
                serde_json::from_str(&compact)
                    .unwrap_or(serde_json::Value::String(compact.into_owned()))
            }
            Err(_) => serde_json::Value::String(format!("{v}")),
        },
        LuaValue::Nil => serde_json::Value::Null,
        LuaValue::Boolean(b) => serde_json::Value::Bool(*b),
        LuaValue::Integer(n) => serde_json::json!(n),
        LuaValue::String(s) => {
            serde_json::Value::String(String::from_utf8_lossy(s.as_bytes()).into_owned())
        }
        _ => serde_json::Value::String(format!("{v}")),
    }
}

/// Format a LuaValue for display, rendering tables as readable JSON.
fn format_value(v: &LuaValue) -> String {
    match v {
        LuaValue::Table(_) => {
            match canonical_serialize(v) {
                Ok(bytes) => {
                    // canonical_serialize produces compact JSON — pretty-print it
                    let compact = String::from_utf8_lossy(&bytes);
                    match serde_json::from_str::<serde_json::Value>(&compact) {
                        Ok(parsed) => serde_json::to_string_pretty(&parsed)
                            .unwrap_or_else(|_| compact.into_owned()),
                        Err(_) => compact.into_owned(),
                    }
                }
                Err(_) => format!("{v}"),
            }
        }
        _ => format!("{v}"),
    }
}

/// Result of a successful pipeline execution.
#[derive(Debug)]
pub struct PipelineResult {
    pub task: String,
    pub model: String,
    pub source: String,
    pub output: VmOutput,
    pub config: VmConfig,
    pub attempts: usize,
    pub token_usage: crate::llm::TokenUsage,
}

/// Verification hashes for a pipeline result.
#[derive(Debug, Clone)]
pub struct VerificationHashes {
    pub program_hash: String,
    pub tape_hash: String,
    pub output_hash: String,
}

/// Compute SHA-256 hex digest of bytes.
fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("sha256:{hash:x}")
}

/// Compute verification hashes for a pipeline result.
pub fn compute_hashes(result: &PipelineResult) -> VerificationHashes {
    let program_hash = sha256_hex(result.source.as_bytes());

    // Tape hash: concatenation of all tool call canonical args + responses
    let mut tape_data = Vec::new();
    for r in &result.output.transcript {
        tape_data.extend_from_slice(&r.args_canonical);
        tape_data.extend_from_slice(&r.response_canonical);
    }
    let tape_hash = sha256_hex(&tape_data);

    let output_hash = sha256_hex(format_value(&result.output.return_value).as_bytes());

    VerificationHashes {
        program_hash,
        tape_hash,
        output_hash,
    }
}

/// Errors from the compile → verify → execute pipeline.
#[derive(Debug)]
#[allow(dead_code)]
pub enum PipelineError {
    Parse(String),
    Compile(String),
    Verify(String),
    Runtime(String, VmError),
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::Parse(msg) => write!(f, "Parse error: {msg}"),
            PipelineError::Compile(msg) => write!(f, "Compile error: {msg}"),
            PipelineError::Verify(msg) => write!(f, "Verify error: {msg}"),
            PipelineError::Runtime(msg, _) => write!(f, "Runtime error: {msg}"),
        }
    }
}

/// Compile Lua source to a verified program.
pub fn compile_and_verify(source: &str) -> Result<CompiledProgram, PipelineError> {
    let ast = parser::parse(source).map_err(|e| PipelineError::Parse(format!("{e:?}")))?;
    let program = compiler::compile(&ast).map_err(|e| PipelineError::Compile(format!("{e:?}")))?;
    bytecode::verify(&program).map_err(|e| PipelineError::Verify(format!("{e:?}")))?;
    Ok(program)
}

/// Execute a compiled program with the given host and config.
pub fn execute<H: HostInterface>(
    program: &CompiledProgram,
    input: LuaValue,
    config: VmConfig,
    host: H,
) -> Result<VmOutput, PipelineError> {
    let mut vm = Vm::new(config, host);
    vm.execute(program, input).map_err(|e| {
        let msg = format_vm_error(&e);
        PipelineError::Runtime(msg, e)
    })
}

/// Format a VmError into a human-readable string for LLM feedback.
pub fn format_vm_error(err: &VmError) -> String {
    match err {
        VmError::GasExhausted => "Gas limit exceeded — program too expensive".into(),
        VmError::MemoryExhausted => "Memory limit exceeded".into(),
        VmError::CallDepthExceeded => "Call depth exceeded — too much recursion".into(),
        VmError::TypeError(msg) => format!("Type error: {msg}"),
        VmError::RuntimeError(val) => format!("Runtime error: {val}"),
        VmError::ToolError(msg) => format!("Tool error: {msg}"),
        VmError::OutputExceeded => "Output size exceeded".into(),
        VmError::WithLine(line, inner) => {
            format!("Error at line {line}: {}", format_vm_error(inner))
        }
    }
}

/// Format a PipelineError into a context string for LLM retry.
pub fn format_error_for_retry(source: &str, err: &PipelineError) -> String {
    let mut ctx = String::new();
    ctx.push_str("Your previous Lua program failed.\n\n");
    ctx.push_str("## Previous program\n```lua\n");
    ctx.push_str(source);
    ctx.push_str("\n```\n\n");
    ctx.push_str("## Error\n");
    ctx.push_str(&err.to_string());
    ctx.push_str("\n\nPlease fix the program. Respond with ONLY the corrected Lua program.");
    ctx
}

/// Format a byte count into a human-readable string with commas.
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

/// Format the execution output for display.
pub fn format_output(result: &PipelineResult) -> String {
    let mut out = String::new();

    out.push_str("═══ luai execution report ═══\n\n");

    out.push_str(&format!("Task:     \"{}\"\n", result.task));
    out.push_str(&format!("Model:    {}\n", result.model));
    out.push_str(&format!("Attempts: {}\n\n", result.attempts));

    out.push_str("── Generated program ──────────────────────────\n");
    out.push_str(&result.source);
    out.push_str("\n\n");

    out.push_str("── Result ─────────────────────────────────────\n");
    out.push_str(&format!(
        "{}\n\n",
        format_value(&result.output.return_value)
    ));

    if !result.output.logs.is_empty() {
        out.push_str("── Logs ───────────────────────────────────────\n");
        for msg in &result.output.logs {
            out.push_str(&format!("  {msg}\n"));
        }
        out.push('\n');
    }

    if !result.output.transcript.is_empty() {
        out.push_str("── Transcript ─────────────────────────────────\n");
        for r in &result.output.transcript {
            let args = String::from_utf8_lossy(&r.args_canonical);
            let status = match r.status {
                ToolCallStatus::Ok => format!("ok ({} bytes)", r.response_bytes),
                ToolCallStatus::Error => format!("error: {}", r.error_message),
            };
            out.push_str(&format!(
                "  [{}] {} args={} → {}\n",
                r.seq, r.tool_name, args, status
            ));
        }
        out.push('\n');
    }

    out.push_str("── Resource usage ─────────────────────────────\n");
    out.push_str(&format!(
        "  Gas:    {} / {}\n",
        format_number(result.output.gas_used),
        format_number(result.config.gas_limit)
    ));
    out.push_str(&format!(
        "  Memory: {} / {} bytes\n",
        format_number(result.output.memory_used),
        format_number(result.config.memory_limit_bytes)
    ));
    out.push_str(&format!(
        "  Tools:  {} / {} calls\n",
        result.output.transcript.len(),
        result.config.max_tool_calls
    ));
    out.push_str(&format!(
        "  LLM:   {} in + {} out = {} tokens\n\n",
        format_number(result.token_usage.input_tokens),
        format_number(result.token_usage.output_tokens),
        format_number(result.token_usage.total())
    ));

    let hashes = compute_hashes(result);
    out.push_str("── Verification ───────────────────────────────\n");
    out.push_str(&format!("  Program hash:  {}\n", hashes.program_hash));
    out.push_str(&format!("  Tape hash:     {}\n", hashes.tape_hash));
    out.push_str(&format!("  Output hash:   {}\n", hashes.output_hash));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::StubHost;

    // ── compile_and_verify ───────────────────────────────────────────

    #[test]
    fn compile_valid_program() {
        let program = compile_and_verify("return 42").unwrap();
        assert!(!program.prototypes.is_empty());
    }

    #[test]
    fn compile_with_tool_call() {
        let source = r#"local r = tool.call("echo", {message = "hi"})
return r.message"#;
        let program = compile_and_verify(source).unwrap();
        assert!(!program.prototypes.is_empty());
    }

    #[test]
    fn compile_parse_error() {
        let err = compile_and_verify("if then end end").unwrap_err();
        assert!(matches!(err, PipelineError::Parse(_)));
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn compile_disallowed_identifier() {
        let err = compile_and_verify("local x = require('foo')").unwrap_err();
        assert!(matches!(err, PipelineError::Parse(_)));
    }

    #[test]
    fn compile_empty_source() {
        // Empty source is valid Lua — returns nil
        let program = compile_and_verify("").unwrap();
        assert!(!program.prototypes.is_empty());
    }

    // ── execute ──────────────────────────────────────────────────────

    #[test]
    fn execute_simple_return() {
        let program = compile_and_verify("return 42").unwrap();
        let output = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        assert_eq!(output.return_value, LuaValue::Integer(42));
    }

    #[test]
    fn execute_with_logs() {
        let program = compile_and_verify(
            r#"log("hello")
log("world")
return 0"#,
        )
        .unwrap();
        let output = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        assert_eq!(output.logs, vec!["hello", "world"]);
    }

    #[test]
    fn execute_tool_call_echo() {
        let source = r#"local r = tool.call("echo", {message = "test"})
return r.message"#;
        let program = compile_and_verify(source).unwrap();
        let output = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        assert_eq!(
            output.return_value,
            LuaValue::String(luai::types::value::LuaString::from_str("test"))
        );
        assert_eq!(output.transcript.len(), 1);
        assert_eq!(output.transcript[0].tool_name, "echo");
    }

    #[test]
    fn execute_tool_call_add() {
        let source = r#"local r = tool.call("add", {a = 10, b = 32})
return r.result"#;
        let program = compile_and_verify(source).unwrap();
        let output = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        assert_eq!(output.return_value, LuaValue::Integer(42));
    }

    #[test]
    fn execute_tool_call_upper() {
        let source = r#"local r = tool.call("upper", {text = "hello"})
return r.result"#;
        let program = compile_and_verify(source).unwrap();
        let output = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        assert_eq!(
            output.return_value,
            LuaValue::String(luai::types::value::LuaString::from_str("HELLO"))
        );
    }

    #[test]
    fn execute_tool_call_time_now() {
        let source = r#"local r = tool.call("time_now", {})
return r.timestamp"#;
        let program = compile_and_verify(source).unwrap();
        let output = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        assert_eq!(output.return_value, LuaValue::Integer(1709654400));
    }

    #[test]
    fn execute_unknown_tool_error() {
        let source = r#"tool.call("nonexistent", {})"#;
        let program = compile_and_verify(source).unwrap();
        let err = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap_err();
        assert!(matches!(err, PipelineError::Runtime(_, _)));
        assert!(err.to_string().contains("Tool error"));
    }

    #[test]
    fn execute_gas_exhaustion() {
        let source = "while true do end";
        let program = compile_and_verify(source).unwrap();
        let mut config = VmConfig::default();
        config.gas_limit = 100;
        let err = execute(&program, LuaValue::Nil, config, StubHost).unwrap_err();
        assert!(err.to_string().contains("Gas limit exceeded"));
    }

    #[test]
    fn execute_multiple_tool_calls() {
        let source = r#"
local r1 = tool.call("add", {a = 1, b = 2})
local r2 = tool.call("add", {a = 3, b = 4})
return r1.result + r2.result
"#;
        let program = compile_and_verify(source).unwrap();
        let output = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        assert_eq!(output.return_value, LuaValue::Integer(10));
        assert_eq!(output.transcript.len(), 2);
    }

    // ── format_vm_error ──────────────────────────────────────────────

    #[test]
    fn format_error_gas() {
        let msg = format_vm_error(&VmError::GasExhausted);
        assert!(msg.contains("Gas limit exceeded"));
    }

    #[test]
    fn format_error_memory() {
        let msg = format_vm_error(&VmError::MemoryExhausted);
        assert!(msg.contains("Memory limit exceeded"));
    }

    #[test]
    fn format_error_depth() {
        let msg = format_vm_error(&VmError::CallDepthExceeded);
        assert!(msg.contains("Call depth exceeded"));
    }

    #[test]
    fn format_error_type() {
        let msg = format_vm_error(&VmError::TypeError("bad type".into()));
        assert!(msg.contains("Type error: bad type"));
    }

    #[test]
    fn format_error_tool() {
        let msg = format_vm_error(&VmError::ToolError("tool broke".into()));
        assert!(msg.contains("Tool error: tool broke"));
    }

    #[test]
    fn format_error_output() {
        let msg = format_vm_error(&VmError::OutputExceeded);
        assert!(msg.contains("Output size exceeded"));
    }

    #[test]
    fn format_error_with_line() {
        let inner = VmError::TypeError("oops".into());
        let msg = format_vm_error(&VmError::WithLine(42, Box::new(inner)));
        assert!(msg.contains("line 42"));
        assert!(msg.contains("Type error: oops"));
    }

    // ── format_error_for_retry ───────────────────────────────────────

    #[test]
    fn retry_context_includes_source_and_error() {
        let err = PipelineError::Parse("unexpected token".into());
        let ctx = format_error_for_retry("return ???", &err);
        assert!(ctx.contains("return ???"));
        assert!(ctx.contains("Parse error"));
        assert!(ctx.contains("unexpected token"));
        assert!(ctx.contains("Please fix the program"));
    }

    // ── helpers ───────────────────────────────────────────────────────

    fn make_result(source: &str, output: VmOutput, attempts: usize) -> PipelineResult {
        PipelineResult {
            task: "test task".into(),
            model: "test-model".into(),
            source: source.into(),
            output,
            config: VmConfig::default(),
            attempts,
            token_usage: crate::llm::TokenUsage::default(),
        }
    }

    // ── format_number ───────────────────────────────────────────────

    #[test]
    fn format_number_small() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(42), "42");
        assert_eq!(format_number(999), "999");
    }

    #[test]
    fn format_number_with_commas() {
        assert_eq!(format_number(1_000), "1,000");
        assert_eq!(format_number(1_234_567), "1,234,567");
        assert_eq!(format_number(16_777_216), "16,777,216");
    }

    // ── format_output ────────────────────────────────────────────────

    #[test]
    fn format_output_simple() {
        let program = compile_and_verify("return 42").unwrap();
        let output = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        let result = make_result("return 42", output, 1);
        let formatted = format_output(&result);
        assert!(formatted.contains("luai execution report"));
        assert!(formatted.contains("Task:     \"test task\""));
        assert!(formatted.contains("Model:    test-model"));
        assert!(formatted.contains("Attempts: 1"));
        assert!(formatted.contains("return 42"));
        assert!(formatted.contains("42")); // return value
        assert!(formatted.contains("Gas:"));
        assert!(formatted.contains("Memory:"));
        assert!(formatted.contains("Tools:  0 / 16 calls"));
        // No logs or transcript sections for this simple program
        assert!(!formatted.contains("── Logs"));
        assert!(!formatted.contains("── Transcript"));
        // Verification section present
        assert!(formatted.contains("── Verification"));
        assert!(formatted.contains("Program hash:  sha256:"));
        assert!(formatted.contains("Tape hash:     sha256:"));
        assert!(formatted.contains("Output hash:   sha256:"));
    }

    #[test]
    fn format_output_with_logs_and_transcript() {
        let source = r#"log("debug info")
local r = tool.call("echo", {message = "hi"})
return 0"#;
        let program = compile_and_verify(source).unwrap();
        let output = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        let result = make_result(source, output, 2);
        let formatted = format_output(&result);
        assert!(formatted.contains("Attempts: 2"));
        assert!(formatted.contains("── Logs"));
        assert!(formatted.contains("debug info"));
        assert!(formatted.contains("── Transcript"));
        assert!(formatted.contains("echo"));
        assert!(formatted.contains("Tools:  1 / 16 calls"));
    }

    #[test]
    fn format_output_resource_limits() {
        let program = compile_and_verify("return 1").unwrap();
        let output = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        let result = make_result("return 1", output, 1);
        let formatted = format_output(&result);
        // Should show used / limit format
        assert!(formatted.contains(" / 200,000\n")); // gas limit
        assert!(formatted.contains(" / 16,777,216 bytes\n")); // memory limit
    }

    // ── compute_hashes ──────────────────────────────────────────────

    #[test]
    fn hashes_deterministic() {
        let program = compile_and_verify("return 42").unwrap();
        let output1 = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        let output2 = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        let r1 = make_result("return 42", output1, 1);
        let r2 = make_result("return 42", output2, 1);
        let h1 = compute_hashes(&r1);
        let h2 = compute_hashes(&r2);
        assert_eq!(h1.program_hash, h2.program_hash);
        assert_eq!(h1.tape_hash, h2.tape_hash);
        assert_eq!(h1.output_hash, h2.output_hash);
    }

    #[test]
    fn hashes_differ_for_different_source() {
        let p1 = compile_and_verify("return 42").unwrap();
        let p2 = compile_and_verify("return 99").unwrap();
        let o1 = execute(&p1, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        let o2 = execute(&p2, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        let r1 = make_result("return 42", o1, 1);
        let r2 = make_result("return 99", o2, 1);
        let h1 = compute_hashes(&r1);
        let h2 = compute_hashes(&r2);
        assert_ne!(h1.program_hash, h2.program_hash);
        assert_ne!(h1.output_hash, h2.output_hash);
    }

    #[test]
    fn hashes_differ_with_tool_calls() {
        let src_no_tool = "return 1";
        let src_tool = r#"local r = tool.call("echo", {message = "hi"})
return 1"#;
        let p1 = compile_and_verify(src_no_tool).unwrap();
        let p2 = compile_and_verify(src_tool).unwrap();
        let o1 = execute(&p1, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        let o2 = execute(&p2, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        let r1 = make_result(src_no_tool, o1, 1);
        let r2 = make_result(src_tool, o2, 1);
        let h1 = compute_hashes(&r1);
        let h2 = compute_hashes(&r2);
        // Same output but different tape (one has tool calls)
        assert_eq!(h1.output_hash, h2.output_hash);
        assert_ne!(h1.tape_hash, h2.tape_hash);
    }

    #[test]
    fn hash_format_starts_with_sha256() {
        let program = compile_and_verify("return 1").unwrap();
        let output = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost).unwrap();
        let result = make_result("return 1", output, 1);
        let hashes = compute_hashes(&result);
        assert!(hashes.program_hash.starts_with("sha256:"));
        assert!(hashes.tape_hash.starts_with("sha256:"));
        assert!(hashes.output_hash.starts_with("sha256:"));
        // SHA-256 hex is 64 chars + "sha256:" prefix = 71
        assert_eq!(hashes.program_hash.len(), 71);
    }

    // ── sha256_hex ──────────────────────────────────────────────────

    #[test]
    fn sha256_known_value() {
        // SHA-256 of empty string
        let h = sha256_hex(b"");
        assert_eq!(
            h,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn string_format_unsupported_returns_error_not_panic() {
        // Reproducer: LLM generates string.format with width specifiers (%04d)
        // and many local variables. Should return a runtime error, not panic.
        let source = r#"
local result = tool.call("time_now", {})
local timestamp = result.timestamp
local seconds = timestamp % 60
local minutes = (timestamp // 60) % 60
local hours = (timestamp // 3600) % 24
local days = timestamp // 86400
local year = 1970
local month = 1
local day = 1
local days_remaining = days
while days_remaining >= 365 do
    if year % 4 == 0 and (year % 100 ~= 0 or year % 400 == 0) then
        if days_remaining >= 366 then
            days_remaining = days_remaining - 366
            year = year + 1
        else
            break
        end
    else
        days_remaining = days_remaining - 365
        year = year + 1
    end
end
local days_in_month = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
if year % 4 == 0 and (year % 100 ~= 0 or year % 400 == 0) then
    days_in_month[2] = 29
end
while days_remaining >= days_in_month[month] do
    days_remaining = days_remaining - days_in_month[month]
    month = month + 1
    if month > 12 then
        month = 1
        year = year + 1
    end
end
day = day + days_remaining
local time_string = string.format("%04d-%02d-%02d %02d:%02d:%02d UTC",
    year, month, day, hours, minutes, seconds)
return time_string
"#;
        let program = compile_and_verify(source).unwrap();
        let result = execute(&program, LuaValue::Nil, VmConfig::default(), StubHost);
        assert!(
            result.is_err(),
            "should return error for unsupported format specifier"
        );
    }
}
