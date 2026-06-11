//! Integration tests for Phase 8: host boundary, transcript, canonical serialization.

use proveno::{
    OracleTape, TapeHost,
    bytecode::verify,
    compiler::compile,
    host::transcript::ToolCallStatus,
    parser::parse,
    types::{
        table::{LuaKey, LuaTable},
        value::{LuaString, LuaValue},
    },
    vm::{
        engine::{HostInterface, Vm, VmConfig},
        gas::VmError,
    },
};

// ── Mock host ─────────────────────────────────────────────────────────────────

/// A mock host that returns fixed responses for named tools.
struct MockHost {
    responses: Vec<(String, Result<LuaTable, String>)>,
    call_index: usize,
}

impl MockHost {
    fn new() -> Self {
        MockHost {
            responses: Vec::new(),
            call_index: 0,
        }
    }

    fn add_ok(&mut self, tool: &str, t: LuaTable) {
        self.responses.push((tool.to_owned(), Ok(t)));
    }

    fn add_err(&mut self, tool: &str, msg: &str) {
        self.responses.push((tool.to_owned(), Err(msg.to_owned())));
    }
}

impl HostInterface for MockHost {
    fn call_tool(&mut self, name: &str, _args: &LuaTable) -> Result<LuaTable, String> {
        if self.call_index >= self.responses.len() {
            return Err(format!("no more mock responses for tool '{}'", name));
        }
        let (expected_name, resp) = &self.responses[self.call_index];
        assert_eq!(name, expected_name, "unexpected tool name");
        self.call_index += 1;
        resp.clone()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn strip_line_info(e: VmError) -> VmError {
    match e {
        VmError::WithLine(_, inner) => *inner,
        other => other,
    }
}

fn run_with_host(
    src: &str,
    host: MockHost,
    config: VmConfig,
) -> Result<proveno::VmOutput, VmError> {
    let block = parse(src).expect("parse failed");
    let program = compile(&block).expect("compile failed");
    verify(&program).expect("verify failed");
    let mut vm = Vm::new(config, host);
    vm.execute(&program, LuaValue::Nil).map_err(strip_line_info)
}

fn make_response(key: &str, val: LuaValue) -> LuaTable {
    let mut t = LuaTable::new();
    t.rawset(LuaKey::String(LuaString::from_str(key)), val)
        .unwrap();
    t
}

fn make_simple_response() -> LuaTable {
    make_response("result", LuaValue::Integer(42))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn single_tool_call_recorded_in_transcript() {
    let mut host = MockHost::new();
    host.add_ok("search", make_simple_response());

    let src = r#"
        local resp = tool.call("search", {query = "x"})
        return resp.result
    "#;

    let output = run_with_host(src, host, VmConfig::default()).unwrap();
    assert_eq!(output.return_value, LuaValue::Integer(42));
    assert_eq!(output.transcript.len(), 1);

    let r = &output.transcript[0];
    assert_eq!(r.seq, 0);
    assert_eq!(r.tool_name, "search");
    assert_eq!(r.status, ToolCallStatus::Ok);
    // args_canonical should be canonical JSON of {query="x"}
    let args_json = String::from_utf8(r.args_canonical.clone()).unwrap();
    assert_eq!(args_json, r#"{"query":"x"}"#);
    // response_hash is 64 hex chars
    assert_eq!(r.response_hash.len(), 64);
    assert!(r.response_hash.chars().all(|c| c.is_ascii_hexdigit()));
    // response_bytes > 0
    assert!(r.response_bytes > 0);
}

#[test]
fn two_tool_calls_seq_increments() {
    let mut host = MockHost::new();
    host.add_ok("first", make_simple_response());
    host.add_ok("second", make_simple_response());

    let src = r#"
        local r1 = tool.call("first", {})
        local r2 = tool.call("second", {})
        return r1.result + r2.result
    "#;

    let output = run_with_host(src, host, VmConfig::default()).unwrap();
    assert_eq!(output.return_value, LuaValue::Integer(84));
    assert_eq!(output.transcript.len(), 2);
    assert_eq!(output.transcript[0].seq, 0);
    assert_eq!(output.transcript[0].tool_name, "first");
    assert_eq!(output.transcript[1].seq, 1);
    assert_eq!(output.transcript[1].tool_name, "second");
}

#[test]
fn tool_error_outside_pcall_terminates() {
    let mut host = MockHost::new();
    host.add_err("broken", "tool failed hard");

    let src = r#"
        local resp = tool.call("broken", {})
        return 99
    "#;

    let err = run_with_host(src, host, VmConfig::default()).unwrap_err();
    assert!(matches!(err, VmError::ToolError(_)));
}

#[test]
fn tool_error_inside_pcall_continues() {
    let mut host = MockHost::new();
    host.add_err("broken", "tool failed");

    let src = r#"
        local ok, err = pcall(function()
            local resp = tool.call("broken", {})
            return resp
        end)
        if ok then return 1 else return 0 end
    "#;

    let output = run_with_host(src, host, VmConfig::default()).unwrap();
    // pcall should catch the ToolError and return false
    assert_eq!(output.return_value, LuaValue::Integer(0));
    // transcript should record the error
    assert_eq!(output.transcript.len(), 1);
    assert_eq!(output.transcript[0].status, ToolCallStatus::Error);
    assert_eq!(output.transcript[0].gas_charged, 0);
}

#[test]
fn max_tool_calls_quota_enforced() {
    let mut host = MockHost::new();
    for _ in 0..3 {
        host.add_ok("t", make_simple_response());
    }

    let config = VmConfig {
        max_tool_calls: 2,
        ..VmConfig::default()
    };

    let src = r#"
        tool.call("t", {})
        tool.call("t", {})
        tool.call("t", {})
        return 99
    "#;

    let err = run_with_host(src, host, config).unwrap_err();
    assert!(matches!(err, VmError::RuntimeError(_)));
    if let VmError::RuntimeError(LuaValue::String(s)) = err {
        assert!(
            String::from_utf8_lossy(s.as_bytes()).contains("limit exceeded"),
            "expected 'limit exceeded' in error message"
        );
    }
}

#[test]
fn max_tool_bytes_in_quota_enforced() {
    // The args {} = 2 bytes ("{}"), so limit of 1 should fail.
    let mut host = MockHost::new();
    host.add_ok("t", make_simple_response());

    let config = VmConfig {
        max_tool_bytes_in: 1,
        ..VmConfig::default()
    };

    let src = r#"
        tool.call("t", {})
        return 1
    "#;

    let err = run_with_host(src, host, config).unwrap_err();
    assert!(matches!(err, VmError::RuntimeError(_)));
}

#[test]
fn max_tool_bytes_out_quota_enforced() {
    let mut host = MockHost::new();
    // Response will be {"result":42} = 13 bytes, limit to 1.
    host.add_ok("t", make_simple_response());

    let config = VmConfig {
        max_tool_bytes_out: 1,
        ..VmConfig::default()
    };

    let src = r#"
        tool.call("t", {})
        return 1
    "#;

    let err = run_with_host(src, host, config).unwrap_err();
    assert!(matches!(err, VmError::RuntimeError(_)));
    if let VmError::RuntimeError(LuaValue::String(s)) = err {
        assert!(
            String::from_utf8_lossy(s.as_bytes()).contains("output"),
            "expected 'output' in error message"
        );
    }
}

#[test]
fn json_encode_deeply_nested_errors() {
    // Build a deeply nested Lua table (depth > 32) and json.encode it.
    // The error should be RuntimeError, caught by pcall.
    let src = r#"
        local function make_deep(n)
            local t = {}
            local inner = t
            for i = 1, n do
                local next_t = {}
                inner.child = next_t
                inner = next_t
            end
            return t
        end
        local deep = make_deep(40)
        local ok, err = pcall(function()
            return json.encode(deep)
        end)
        if ok then return 1 else return 0 end
    "#;

    let host = MockHost::new();
    let output = run_with_host(src, host, VmConfig::default()).unwrap();
    assert_eq!(output.return_value, LuaValue::Integer(0));
}

#[test]
fn json_encode_routes_through_canonical_serializer() {
    // Verify that json.encode produces canonical output consistent with the
    // canonical serializer (array for consecutive integer keys, object otherwise).
    let src = r#"
        local arr = {10, 20, 30}
        local obj = {a = 1}
        local ea = json.encode(arr)
        local eo = json.encode(obj)
        return ea .. "|" .. eo
    "#;

    let host = MockHost::new();
    let output = run_with_host(src, host, VmConfig::default()).unwrap();
    assert_eq!(
        output.return_value,
        LuaValue::String(LuaString::from_str("[10,20,30]|{\"a\":1}"))
    );
}

#[test]
fn tool_call_args_canonical_matches_json_encode() {
    // The args_canonical in the transcript should match what json.encode produces.
    let mut host = MockHost::new();
    host.add_ok("search", make_simple_response());

    let src = r#"
        local args = {query = "hello", count = 5}
        local resp = tool.call("search", args)
        return resp.result
    "#;

    let output = run_with_host(src, host, VmConfig::default()).unwrap();
    assert_eq!(output.return_value, LuaValue::Integer(42));

    let r = &output.transcript[0];
    let args_json = String::from_utf8(r.args_canonical.clone()).unwrap();
    // Canonical order: integers before strings, so "count" (integer val) comes first? No —
    // the keys "count" and "query" are both strings, sorted lexicographically: "count" < "query"
    assert_eq!(args_json, r#"{"count":5,"query":"hello"}"#);
}

#[test]
fn transcript_empty_on_no_tool_calls() {
    let src = r#"
        return 1 + 2
    "#;
    let host = MockHost::new();
    let output = run_with_host(src, host, VmConfig::default()).unwrap();
    assert_eq!(output.transcript.len(), 0);
}

#[test]
fn tool_error_transcript_records_args() {
    let mut host = MockHost::new();
    host.add_err("broken", "failed");

    let src = r#"
        local ok, err = pcall(function()
            tool.call("broken", {key = "val"})
        end)
        return 1
    "#;

    let output = run_with_host(src, host, VmConfig::default()).unwrap();
    assert_eq!(output.transcript.len(), 1);
    let r = &output.transcript[0];
    assert_eq!(r.status, ToolCallStatus::Error);
    let args_json = String::from_utf8(r.args_canonical.clone()).unwrap();
    assert_eq!(args_json, r#"{"key":"val"}"#);
    assert_eq!(r.response_hash, "");
    assert_eq!(r.response_bytes, 0);
}

#[test]
fn gas_charged_for_tool_call() {
    let mut host = MockHost::new();
    host.add_ok("t", make_simple_response());

    let src = r#"
        tool.call("t", {})
        return 1
    "#;

    let output = run_with_host(src, host, VmConfig::default()).unwrap();
    // Gas charged must include the base tool call cost.
    let r = &output.transcript[0];
    assert!(
        r.gas_charged >= 100,
        "expected gas_charged >= 100, got {}",
        r.gas_charged
    );
}

// ── Tape replay helper ─────────────────────────────────────────────────────────

fn run_with_tape(
    src: &str,
    tape: OracleTape,
    config: VmConfig,
) -> Result<proveno::VmOutput, VmError> {
    let block = parse(src).expect("parse failed");
    let program = compile(&block).expect("compile failed");
    verify(&program).expect("verify failed");
    let mut vm = Vm::new(config, TapeHost::new(tape));
    vm.execute(&program, LuaValue::Nil).map_err(|e| match e {
        VmError::WithLine(_, inner) => *inner,
        other => other,
    })
}

// ── Tape round-trip tests ──────────────────────────────────────────────────────

#[test]
fn tape_replay_matches_dry_run_return_value() {
    let src = r#"
        local resp = tool.call("search", {query = "hello"})
        return resp.result
    "#;

    // Dry run with mock host.
    let mut host = MockHost::new();
    host.add_ok("search", make_simple_response());
    let dry_out = run_with_host(src, host, VmConfig::default()).unwrap();
    assert_eq!(dry_out.return_value, LuaValue::Integer(42));

    // Replay with tape.
    let tape = OracleTape::from_records(&dry_out.transcript);
    let replay_out = run_with_tape(src, tape, VmConfig::default()).unwrap();

    assert_eq!(replay_out.return_value, dry_out.return_value);
}

#[test]
fn tape_replay_matches_dry_run_gas_and_memory() {
    let src = r#"
        local r1 = tool.call("t1", {a = 1})
        local r2 = tool.call("t2", {b = 2})
        return r1.result + r2.result
    "#;

    let mut host = MockHost::new();
    host.add_ok("t1", make_simple_response());
    host.add_ok("t2", make_response("result", LuaValue::Integer(8)));
    let dry_out = run_with_host(src, host, VmConfig::default()).unwrap();
    assert_eq!(dry_out.return_value, LuaValue::Integer(50));

    let tape = OracleTape::from_records(&dry_out.transcript);
    let replay_out = run_with_tape(src, tape, VmConfig::default()).unwrap();

    assert_eq!(replay_out.return_value, dry_out.return_value);
    assert_eq!(replay_out.gas_used, dry_out.gas_used);
    assert_eq!(replay_out.memory_used, dry_out.memory_used);
}

#[test]
fn tape_replay_with_error_entry_propagates_error() {
    let src = r#"
        local ok, err = pcall(function()
            tool.call("broken", {})
        end)
        if ok then return 1 else return 0 end
    "#;

    // Dry run: host returns error, pcall catches it.
    let mut host = MockHost::new();
    host.add_err("broken", "tool failed");
    let dry_out = run_with_host(src, host, VmConfig::default()).unwrap();
    assert_eq!(dry_out.return_value, LuaValue::Integer(0));

    // Replay: TapeHost replays the error; pcall still catches it.
    let tape = OracleTape::from_records(&dry_out.transcript);
    let replay_out = run_with_tape(src, tape, VmConfig::default()).unwrap();
    assert_eq!(replay_out.return_value, dry_out.return_value);
}

#[test]
fn tape_exhausted_returns_error() {
    let src = r#"
        tool.call("t", {})
        return 1
    "#;

    // Build an empty tape (no entries).
    let tape = OracleTape::new();
    let err = run_with_tape(src, tape, VmConfig::default()).unwrap_err();
    // TapeHost exhaustion surfaces as a ToolError.
    assert!(matches!(err, VmError::ToolError(_)));
    if let VmError::ToolError(msg) = err {
        assert!(msg.contains("exhausted"), "expected 'exhausted' in: {msg}");
    }
}

#[test]
fn tape_commitment_hash_matches_between_runs() {
    let src = r#"
        local r = tool.call("tool", {x = 1})
        return r.result
    "#;

    let mut host1 = MockHost::new();
    host1.add_ok("tool", make_simple_response());
    let out1 = run_with_host(src, host1, VmConfig::default()).unwrap();

    let mut host2 = MockHost::new();
    host2.add_ok("tool", make_simple_response());
    let out2 = run_with_host(src, host2, VmConfig::default()).unwrap();

    let tape1 = OracleTape::from_records(&out1.transcript);
    let tape2 = OracleTape::from_records(&out2.transcript);

    // Two identical dry runs produce the same commitment hash.
    assert_eq!(tape1.commitment_hash(), tape2.commitment_hash());
}

#[test]
fn tape_commitment_hash_differs_for_different_responses() {
    let src = r#"
        local r = tool.call("tool", {})
        return r.result
    "#;

    let mut host_a = MockHost::new();
    host_a.add_ok("tool", make_response("result", LuaValue::Integer(1)));
    let out_a = run_with_host(src, host_a, VmConfig::default()).unwrap();

    let mut host_b = MockHost::new();
    host_b.add_ok("tool", make_response("result", LuaValue::Integer(2)));
    let out_b = run_with_host(src, host_b, VmConfig::default()).unwrap();

    let tape_a = OracleTape::from_records(&out_a.transcript);
    let tape_b = OracleTape::from_records(&out_b.transcript);

    assert_ne!(tape_a.commitment_hash(), tape_b.commitment_hash());
}

#[test]
fn tape_replay_transcript_length_matches() {
    // Replay itself also records a transcript (via TapeHost).
    let src = r#"
        tool.call("a", {})
        tool.call("b", {})
        return 1
    "#;

    let mut host = MockHost::new();
    host.add_ok("a", make_simple_response());
    host.add_ok("b", make_simple_response());
    let dry_out = run_with_host(src, host, VmConfig::default()).unwrap();
    assert_eq!(dry_out.transcript.len(), 2);

    let tape = OracleTape::from_records(&dry_out.transcript);
    let replay_out = run_with_tape(src, tape, VmConfig::default()).unwrap();
    assert_eq!(replay_out.transcript.len(), 2);
}
