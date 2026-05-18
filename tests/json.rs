//! Integration tests for Phase 10 — json module.
//!
//! These tests compile + execute Lua source through the full pipeline and
//! cover: encode/decode correctness, agent-workflow patterns, roundtrips,
//! error recovery via pcall, and gas/memory accounting.

use luai::{
    bytecode::verify,
    compiler::compile,
    parser::parse,
    types::value::{LuaString, LuaValue},
    vm::{
        engine::{NoopHost, Vm, VmConfig, VmOutput},
        gas::VmError,
    },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn strip_line_info(e: VmError) -> VmError {
    match e {
        VmError::WithLine(_, inner) => *inner,
        other => other,
    }
}

fn run_with_config(src: &str, config: VmConfig) -> Result<VmOutput, VmError> {
    let block = parse(src).expect("parse failed");
    let program = compile(&block).expect("compile failed");
    verify(&program).expect("verify failed");
    let mut vm = Vm::new(config, NoopHost);
    vm.execute(&program, LuaValue::Nil).map_err(strip_line_info)
}

fn run(src: &str) -> Result<VmOutput, VmError> {
    run_with_config(src, VmConfig::default())
}

fn run_ok(src: &str) -> VmOutput {
    run(src).expect("execution failed")
}

fn int(n: i64) -> LuaValue {
    LuaValue::Integer(n)
}

fn s(text: &str) -> LuaValue {
    LuaValue::String(LuaString::from_str(text))
}

fn assert_returns(src: &str, expected: LuaValue) {
    let out = run_ok(src);
    assert_eq!(out.return_value, expected, "source: {src}");
}

fn assert_returns_int(src: &str, expected: i64) {
    assert_returns(src, int(expected));
}

fn assert_returns_str(src: &str, expected: &str) {
    assert_returns(src, s(expected));
}

fn assert_returns_nil(src: &str) {
    assert_returns(src, LuaValue::Nil);
}

fn assert_returns_bool(src: &str, expected: bool) {
    assert_returns(src, LuaValue::Boolean(expected));
}

fn assert_runtime_err(src: &str) {
    let err = run(src).unwrap_err();
    assert!(
        matches!(err, VmError::RuntimeError(_)),
        "expected RuntimeError, got {err:?}"
    );
}

// ── json.encode ───────────────────────────────────────────────────────────────

#[test]
fn json_encode_nil_integration() {
    assert_returns_str("return json.encode(nil)", "null");
}

#[test]
fn json_encode_bool_integration() {
    assert_returns_str("return json.encode(true)", "true");
    assert_returns_str("return json.encode(false)", "false");
}

#[test]
fn json_encode_integer_integration() {
    assert_returns_str("return json.encode(42)", "42");
}

#[test]
fn json_encode_negative_integer_integration() {
    assert_returns_str("return json.encode(-7)", "-7");
}

#[test]
fn json_encode_string_integration() {
    assert_returns_str(r#"return json.encode("hello")"#, r#""hello""#);
}

#[test]
fn json_encode_string_with_quotes_integration() {
    assert_returns_str(r#"return json.encode('say "hi"')"#, r#""say \"hi\"""#);
}

#[test]
fn json_encode_array_integration() {
    assert_returns_str(
        r#"
        local t = {10, 20, 30}
        return json.encode(t)
        "#,
        "[10,20,30]",
    );
}

#[test]
fn json_encode_nested_array_integration() {
    assert_returns_str(
        r#"
        local t = {{1, 2}, {3, 4}}
        return json.encode(t)
        "#,
        "[[1,2],[3,4]]",
    );
}

#[test]
fn json_encode_empty_table_is_object_integration() {
    assert_returns_str("return json.encode({})", "{}");
}

#[test]
fn json_encode_object_key_ordering_integration() {
    // Keys should appear in sorted order; mixed int+string keys → object.
    let out = run_ok(
        r#"
        local t = {}
        t["b"] = 2
        t["a"] = 1
        return json.encode(t)
    "#,
    );
    // Keys sorted: "a" < "b".
    assert_eq!(out.return_value, s(r#"{"a":1,"b":2}"#));
}

#[test]
fn json_encode_function_error_pcall_integration() {
    assert_returns_bool(
        r#"
        local ok, err = pcall(function()
            return json.encode(json.encode)
        end)
        return ok
        "#,
        false,
    );
}

#[test]
fn json_encode_depth_exceeded_pcall_integration() {
    // Build a 33-deep nested table structure in Lua, then encode — depth check fires.
    let src = r#"
        local function make_deep(n)
            if n == 0 then return {} end
            local t = {}
            t[1] = make_deep(n - 1)
            return t
        end
        local deep = make_deep(33)
        local ok, err = pcall(json.encode, deep)
        return ok
    "#;
    assert_returns_bool(src, false);
}

// ── json.decode ───────────────────────────────────────────────────────────────

#[test]
fn json_decode_null_integration() {
    assert_returns_nil(r#"return json.decode("null")"#);
}

#[test]
fn json_decode_bool_integration() {
    assert_returns_bool(r#"return json.decode("true")"#, true);
    assert_returns_bool(r#"return json.decode("false")"#, false);
}

#[test]
fn json_decode_integer_integration() {
    assert_returns_int(r#"return json.decode("42")"#, 42);
}

#[test]
fn json_decode_string_integration() {
    assert_returns_str(r#"return json.decode('"hello"')"#, "hello");
}

#[test]
fn json_decode_array_length_integration() {
    assert_returns_int(r#"return #json.decode("[1,2,3]")"#, 3);
}

#[test]
fn json_decode_object_field_access_integration() {
    assert_returns_int(r#"return json.decode('{"x":99}')["x"]"#, 99);
}

#[test]
fn json_decode_nested_access_integration() {
    assert_returns_int(r#"return json.decode('{"a":{"b":42}}')["a"]["b"]"#, 42);
}

#[test]
fn json_decode_fractional_error_pcall_integration() {
    assert_returns_bool(
        r#"
        local ok, err = pcall(function()
            return json.decode("3.14")
        end)
        return ok
        "#,
        false,
    );
}

#[test]
fn json_decode_trailing_garbage_error_pcall_integration() {
    assert_returns_bool(
        r#"
        local ok, err = pcall(function()
            return json.decode("42 garbage")
        end)
        return ok
        "#,
        false,
    );
}

#[test]
fn json_decode_depth_exceeded_pcall_integration() {
    // Build a deeply-nested JSON string in Lua and try to decode it.
    let src = r#"
        local open = ""
        local close = ""
        for i = 1, 33 do
            open = open .. "["
            close = close .. "]"
        end
        local json_str = open .. "1" .. close
        local ok, err = pcall(json.decode, json_str)
        return ok
    "#;
    assert_returns_bool(src, false);
}

// ── Roundtrip tests ───────────────────────────────────────────────────────────

#[test]
fn json_roundtrip_array_integration() {
    assert_returns_int(
        r#"
        local t = {1, 2, 3}
        local decoded = json.decode(json.encode(t))
        return decoded[2]
        "#,
        2,
    );
}

#[test]
fn json_roundtrip_object_integration() {
    assert_returns_str(
        r#"
        local t = {}
        t["key"] = "value"
        local decoded = json.decode(json.encode(t))
        return decoded["key"]
        "#,
        "value",
    );
}

#[test]
fn json_roundtrip_nested_integration() {
    assert_returns_int(
        r#"
        local t = {}
        t["inner"] = {10, 20, 30}
        local decoded = json.decode(json.encode(t))
        return decoded["inner"][2]
        "#,
        20,
    );
}

#[test]
fn json_roundtrip_preserves_order_integration() {
    // encode → decode → encode should produce identical output.
    let out = run_ok(
        r#"
        local t = {}
        t["a"] = 1
        t["b"] = 2
        t["c"] = 3
        local first = json.encode(t)
        local second = json.encode(json.decode(first))
        return first == second
    "#,
    );
    assert_eq!(out.return_value, LuaValue::Boolean(true));
}

// ── Agent-workflow patterns ───────────────────────────────────────────────────

#[test]
fn json_agent_parse_tool_result() {
    // Simulate parsing a JSON tool response and extracting a field.
    assert_returns_int(
        r#"
        local resp = json.decode('{"status":"ok","value":42}')
        return resp["value"]
        "#,
        42,
    );
}

#[test]
fn json_agent_build_request() {
    // Build a JSON request object and encode it (keys sorted).
    assert_returns_str(
        r#"
        local req = {}
        req["action"] = "lookup"
        req["id"] = 99
        return json.encode(req)
        "#,
        r#"{"action":"lookup","id":99}"#,
    );
}

#[test]
fn json_agent_accumulate_results() {
    // Decode multiple items, aggregate totals.
    assert_returns_int(
        r#"
        local items = json.decode('[{"n":1},{"n":2},{"n":3}]')
        local total = 0
        for i = 1, #items do
            total = total + items[i]["n"]
        end
        return total
        "#,
        6,
    );
}

#[test]
fn json_agent_error_recovery() {
    // pcall recovers from a bad JSON string.
    assert_returns_bool(
        r#"
        local ok, err = pcall(function()
            return json.decode("not-json")
        end)
        return ok
        "#,
        false,
    );
}

#[test]
fn json_agent_nested_structure() {
    // Build, encode, decode, and re-access a nested structure.
    assert_returns_int(
        r#"
        local data = {}
        data["name"] = "agent"
        data["scores"] = {10, 20, 30}
        local encoded = json.encode(data)
        local decoded = json.decode(encoded)
        return decoded["scores"][2]
        "#,
        20,
    );
}

// ── Gas and memory accounting ─────────────────────────────────────────────────

#[test]
fn json_encode_charges_gas() {
    // Encoding a non-trivial value should charge at least len(result) gas.
    let out = run_ok(r#"return json.encode({1, 2, 3, 4, 5})"#);
    // The encoded string is "[1,2,3,4,5]" = 11 bytes.
    assert!(
        out.gas_used >= 11,
        "expected gas_used >= 11, got {}",
        out.gas_used
    );
}

#[test]
fn json_decode_charges_gas() {
    // Decoding should charge at least len(input) gas.
    // Input "[1,2,3]" = 7 bytes.
    let out = run_ok(r#"return json.decode("[1,2,3]")"#);
    assert!(
        out.gas_used >= 7,
        "expected gas_used >= 7, got {}",
        out.gas_used
    );
}

#[test]
fn json_decode_table_memory_charged() {
    // A very tight memory budget should cause decoding a large array to fail.
    let config = VmConfig {
        memory_limit_bytes: 200,
        ..VmConfig::default()
    };
    let err = run_with_config(
        r#"return json.decode("[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17]")"#,
        config,
    )
    .unwrap_err();
    assert_eq!(err, VmError::MemoryExhausted);

    // With an adequate budget it must succeed.
    let out = run_ok(r#"return #json.decode("[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17]")"#);
    assert_eq!(out.return_value, int(17));
}
