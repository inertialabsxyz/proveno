//! Integration tests for Phase 7 standard library builtins.
//!
//! These tests compile + execute Lua source through the full pipeline.

use proveno::types::value::LuaValue;
use proveno::{
    bytecode::verify,
    compiler::compile,
    parser::parse,
    vm::engine::{NoopHost, Vm, VmConfig, VmOutput},
    vm::gas::VmError,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn strip_line_info(e: VmError) -> VmError {
    match e {
        VmError::WithLine(_, inner) => *inner,
        other => other,
    }
}

fn run(src: &str) -> Result<VmOutput, VmError> {
    let block = parse(src).expect("parse failed");
    let program = compile(&block).expect("compile failed");
    verify(&program).expect("verify failed");
    let mut vm = Vm::new(VmConfig::default(), NoopHost);
    vm.execute(&program, LuaValue::Nil).map_err(strip_line_info)
}

fn run_ok(src: &str) -> VmOutput {
    run(src).expect("execution failed")
}

fn int(n: i64) -> LuaValue {
    LuaValue::Integer(n)
}

fn s(text: &str) -> LuaValue {
    use proveno::types::value::LuaString;
    LuaValue::String(LuaString::from_str(text))
}

fn assert_returns(src: &str, expected: LuaValue) {
    let out = run_ok(src);
    assert_eq!(out.return_value, expected, "source: {}", src);
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

fn assert_returns_true(src: &str) {
    assert_returns(src, LuaValue::Boolean(true));
}

fn assert_returns_false(src: &str) {
    assert_returns(src, LuaValue::Boolean(false));
}

// ── type() ────────────────────────────────────────────────────────────────────

#[test]
fn type_of_nil() {
    assert_returns_str("return type(nil)", "nil");
}

#[test]
fn type_of_boolean() {
    assert_returns_str("return type(true)", "boolean");
}

#[test]
fn type_of_integer() {
    assert_returns_str("return type(42)", "integer");
}

#[test]
fn type_of_string() {
    assert_returns_str(r#"return type("hello")"#, "string");
}

#[test]
fn type_of_table() {
    assert_returns_str("return type({})", "table");
}

#[test]
fn type_of_function() {
    assert_returns_str("local f = function() end return type(f)", "function");
}

// ── tostring() ────────────────────────────────────────────────────────────────

#[test]
fn tostring_nil() {
    assert_returns_str("return tostring(nil)", "nil");
}

#[test]
fn tostring_true() {
    assert_returns_str("return tostring(true)", "true");
}

#[test]
fn tostring_false() {
    assert_returns_str("return tostring(false)", "false");
}

#[test]
fn tostring_integer() {
    assert_returns_str("return tostring(123)", "123");
}

#[test]
fn tostring_negative_integer() {
    assert_returns_str("return tostring(-7)", "-7");
}

#[test]
fn tostring_string_identity() {
    assert_returns_str(r#"return tostring("hello")"#, "hello");
}

// ── tonumber() ────────────────────────────────────────────────────────────────

#[test]
fn tonumber_integer_passthrough() {
    assert_returns_int("return tonumber(42)", 42);
}

#[test]
fn tonumber_valid_string() {
    assert_returns_int(r#"return tonumber("123")"#, 123);
}

#[test]
fn tonumber_negative_string() {
    assert_returns_int(r#"return tonumber("-7")"#, -7);
}

#[test]
fn tonumber_invalid_string_returns_nil() {
    assert_returns_nil(r#"return tonumber("abc")"#);
}

#[test]
fn tonumber_float_string_returns_nil() {
    assert_returns_nil(r#"return tonumber("3.14")"#);
}

// ── log() ─────────────────────────────────────────────────────────────────────

#[test]
fn log_appends_to_output() {
    let out = run_ok(r#"log("hello") log("world")"#);
    assert_eq!(out.logs, vec!["hello", "world"]);
}

// ── error() ───────────────────────────────────────────────────────────────────

#[test]
fn error_raises_runtime_error() {
    let err = run(r#"error("oops")"#).unwrap_err();
    assert!(matches!(err, VmError::RuntimeError(_)));
}

#[test]
fn error_caught_by_pcall() {
    assert_returns_true(r#"local ok, _ = pcall(function() error("x") end) return ok == false"#);
}

// ── select() ─────────────────────────────────────────────────────────────────

#[test]
fn select_returns_nth_element() {
    assert_returns_int("return select(2, 10, 20, 30)", 20);
}

#[test]
fn select_hash_returns_count() {
    assert_returns_int("return select(\"#\", 10, 20, 30)", 3);
}

// ── unpack() ─────────────────────────────────────────────────────────────────

#[test]
fn unpack_sums_elements() {
    // unpack returns multiple values; only first captured by single assignment
    assert_returns_int(
        r#"
local t = {10, 20, 30}
local x = unpack(t)
return x
"#,
        10,
    );
}

#[test]
fn unpack_with_range_first() {
    assert_returns_int(
        r#"
local t = {10, 20, 30, 40}
local x = unpack(t, 2, 4)
return x
"#,
        20,
    );
}

// ── string.len ────────────────────────────────────────────────────────────────

#[test]
fn string_len_basic() {
    assert_returns_int(r#"return string.len("hello")"#, 5);
}

#[test]
fn string_len_empty() {
    assert_returns_int(r#"return string.len("")"#, 0);
}

// ── string.sub ────────────────────────────────────────────────────────────────

#[test]
fn string_sub_basic() {
    assert_returns_str(r#"return string.sub("hello", 2, 4)"#, "ell");
}

#[test]
fn string_sub_to_end() {
    assert_returns_str(r#"return string.sub("hello", 3)"#, "llo");
}

#[test]
fn string_sub_negative_end() {
    assert_returns_str(r#"return string.sub("hello", 1, -2)"#, "hell");
}

#[test]
fn string_sub_negative_start() {
    assert_returns_str(r#"return string.sub("hello", -3)"#, "llo");
}

// ── string.find ───────────────────────────────────────────────────────────────

#[test]
fn string_find_found() {
    assert_returns_int(
        r#"local i, j = string.find("hello world", "world") return i"#,
        7,
    );
}

#[test]
fn string_find_not_found_returns_nil() {
    assert_returns_nil(r#"local i, j = string.find("hello", "xyz") return i"#);
}

#[test]
fn string_find_metachar_error() {
    let err = run(r#"string.find("hello", "h.l")"#).unwrap_err();
    assert!(matches!(err, VmError::RuntimeError(_)));
}

// ── string.find_literal ───────────────────────────────────────────────────────

#[test]
fn string_find_literal_matches_dot_in_price() {
    assert_returns_int(
        r#"local i, j = string.find_literal("3245.67", ".") return i"#,
        5,
    );
}

#[test]
fn string_find_literal_splits_decimal_into_int_and_frac() {
    // The motivating use case: parse "3245.67" into integer cents (324567)
    // without `tonumber` silently returning nil. Pins that the builtin supports
    // the canonical price-parsing pattern recommended in the system prompt.
    assert_returns_int(
        r#"
local raw = "3245.67"
local dot = string.find_literal(raw, ".")
local int_part = string.sub(raw, 1, dot - 1)
local frac_part = string.sub(raw, dot + 1)
return tonumber(int_part) * 100 + tonumber(frac_part)
"#,
        324567,
    );
}

#[test]
fn string_find_literal_matches_multi_metachar_substring() {
    // Returns the first return value (start index). Pins that a needle
    // containing several pattern metacharacters is treated literally.
    assert_returns_int(
        r#"local i, j = string.find_literal("x a.b*c y", "a.b*c") return i"#,
        3,
    );
}

#[test]
fn string_find_literal_not_found_returns_nil() {
    assert_returns_nil(r#"local i, j = string.find_literal("hello", "xyz") return i"#);
}

// ── string.upper / lower ──────────────────────────────────────────────────────

#[test]
fn string_upper() {
    assert_returns_str(r#"return string.upper("hello")"#, "HELLO");
}

#[test]
fn string_lower() {
    assert_returns_str(r#"return string.lower("HELLO")"#, "hello");
}

// ── string.rep ────────────────────────────────────────────────────────────────

#[test]
fn string_rep_basic() {
    assert_returns_str(r#"return string.rep("ab", 3)"#, "ababab");
}

#[test]
fn string_rep_zero() {
    assert_returns_str(r#"return string.rep("ab", 0)"#, "");
}

// ── string.byte / char ────────────────────────────────────────────────────────

#[test]
fn string_byte_single() {
    assert_returns_int(r#"return string.byte("A")"#, 65);
}

#[test]
fn string_char_basic() {
    assert_returns_str("return string.char(65, 66, 67)", "ABC");
}

#[test]
fn string_byte_char_roundtrip() {
    // string.byte with single char, string.char converts it back
    assert_returns_str(r#"local b = string.byte("h") return string.char(b)"#, "h");
}

// ── string.format ─────────────────────────────────────────────────────────────

#[test]
fn string_format_d() {
    assert_returns_str(r#"return string.format("%d", 42)"#, "42");
}

#[test]
fn string_format_s() {
    assert_returns_str(
        r#"return string.format("hello %s", "world")"#,
        "hello world",
    );
}

#[test]
fn string_format_x() {
    assert_returns_str(r#"return string.format("%x", 255)"#, "ff");
}

#[test]
fn string_format_percent() {
    assert_returns_str(r#"return string.format("100%%")"#, "100%");
}

#[test]
fn string_format_mixed() {
    assert_returns_str(
        r#"return string.format("%d + %d = %d", 1, 2, 3)"#,
        "1 + 2 = 3",
    );
}

// ── math.abs ──────────────────────────────────────────────────────────────────

#[test]
fn math_abs_positive() {
    assert_returns_int("return math.abs(5)", 5);
}

#[test]
fn math_abs_negative() {
    assert_returns_int("return math.abs(-5)", 5);
}

#[test]
fn math_abs_zero() {
    assert_returns_int("return math.abs(0)", 0);
}

// ── math.min / max ────────────────────────────────────────────────────────────

#[test]
fn math_min_basic() {
    assert_returns_int("return math.min(3, 1, 4)", 1);
}

#[test]
fn math_max_basic() {
    assert_returns_int("return math.max(3, 1, 4)", 4);
}

// ── math.scale_div ────────────────────────────────────────────────────────────

#[test]
fn math_scale_div_basic() {
    // (10 * 100) // 3 = 333
    assert_returns_int("return math.scale_div(10, 3, 100)", 333);
}

#[test]
fn math_scale_div_exact() {
    // (6 * 2) // 3 = 4
    assert_returns_int("return math.scale_div(6, 3, 2)", 4);
}

// ── math constants ────────────────────────────────────────────────────────────

#[test]
fn math_maxinteger() {
    assert_returns_int("return math.maxinteger", i64::MAX);
}

#[test]
fn math_mininteger() {
    assert_returns_int("return math.mininteger", i64::MIN);
}

// ── table.insert ─────────────────────────────────────────────────────────────

#[test]
fn table_insert_append() {
    assert_returns_int(
        r#"
local t = {10, 20}
table.insert(t, 30)
return t[3]
"#,
        30,
    );
}

#[test]
fn table_insert_at_pos() {
    assert_returns_int(
        r#"
local t = {1, 3}
table.insert(t, 2, 2)
return t[2]
"#,
        2,
    );
}

#[test]
fn table_insert_shifts_elements() {
    assert_returns_int(
        r#"
local t = {1, 3}
table.insert(t, 2, 2)
return t[3]
"#,
        3,
    );
}

// ── table.remove ─────────────────────────────────────────────────────────────

#[test]
fn table_remove_last() {
    assert_returns_int(
        r#"
local t = {10, 20, 30}
local v = table.remove(t)
return v
"#,
        30,
    );
}

#[test]
fn table_remove_at_pos() {
    assert_returns_int(
        r#"
local t = {10, 20, 30}
local v = table.remove(t, 2)
return v
"#,
        20,
    );
}

#[test]
fn table_remove_shrinks_length() {
    assert_returns_int(
        r#"
local t = {10, 20, 30}
table.remove(t)
return #t
"#,
        2,
    );
}

// ── table.concat ─────────────────────────────────────────────────────────────

#[test]
fn table_concat_with_sep() {
    assert_returns_str(
        r#"
local t = {"a", "b", "c"}
return table.concat(t, ",")
"#,
        "a,b,c",
    );
}

#[test]
fn table_concat_no_sep() {
    assert_returns_str(
        r#"
local t = {"x", "y", "z"}
return table.concat(t)
"#,
        "xyz",
    );
}

#[test]
fn table_concat_partial_range() {
    assert_returns_str(
        r#"
local t = {"a", "b", "c", "d", "e"}
return table.concat(t, "-", 2, 4)
"#,
        "b-c-d",
    );
}

// ── table.sort ────────────────────────────────────────────────────────────────

#[test]
fn table_sort_integers() {
    assert_returns_int(
        r#"
local t = {3, 1, 4, 1, 5, 9, 2, 6}
table.sort(t)
return t[1]
"#,
        1,
    );
}

#[test]
fn table_sort_integers_last_elem() {
    assert_returns_int(
        r#"
local t = {3, 1, 4, 1, 5, 9, 2, 6}
table.sort(t)
return t[8]
"#,
        9,
    );
}

#[test]
fn table_sort_strings() {
    assert_returns_str(
        r#"
local t = {"banana", "apple", "cherry"}
table.sort(t)
return t[1]
"#,
        "apple",
    );
}

#[test]
fn table_sort_custom_comp_descending() {
    assert_returns_int(
        r#"
local t = {3, 1, 4, 1, 5}
table.sort(t, function(a, b) return a > b end)
return t[1]
"#,
        5,
    );
}

// ── table.move ────────────────────────────────────────────────────────────────

#[test]
fn table_move_basic() {
    assert_returns_int(
        r#"
local t = {10, 20, 30, 40}
table.move(t, 1, 3, 2)
return t[2]
"#,
        10,
    );
}

// ── json.encode ───────────────────────────────────────────────────────────────

#[test]
fn json_encode_null() {
    assert_returns_str("return json.encode(nil)", "null");
}

#[test]
fn json_encode_integer() {
    assert_returns_str("return json.encode(42)", "42");
}

#[test]
fn json_encode_string() {
    assert_returns_str(r#"return json.encode("hello")"#, r#""hello""#);
}

#[test]
fn json_encode_array() {
    assert_returns_str("return json.encode({10, 20, 30})", "[10,20,30]");
}

#[test]
fn json_encode_bool() {
    assert_returns_str("return json.encode(true)", "true");
}

// ── json.decode ───────────────────────────────────────────────────────────────

#[test]
fn json_decode_integer() {
    assert_returns_int("return json.decode(\"42\")", 42);
}

#[test]
fn json_decode_null() {
    assert_returns_nil("return json.decode(\"null\")");
}

#[test]
fn json_decode_string() {
    assert_returns_str(r#"return json.decode("\"hello\"")"#, "hello");
}

#[test]
fn json_decode_array_element() {
    assert_returns_int(
        r#"
local t = json.decode("[1,2,3]")
return t[2]
"#,
        2,
    );
}

#[test]
fn json_decode_object_field() {
    assert_returns_int(
        r#"
local t = json.decode("{\"x\":99}")
return t["x"]
"#,
        99,
    );
}

#[test]
fn json_decode_fractional_error() {
    let err = run(r#"json.decode("3.14")"#).unwrap_err();
    assert!(matches!(err, VmError::RuntimeError(_)));
}

// ── json roundtrip ────────────────────────────────────────────────────────────

#[test]
fn json_roundtrip_array() {
    assert_returns_str(
        r#"
local t = {1, 2, 3}
local s = json.encode(t)
local t2 = json.decode(s)
return json.encode(t2)
"#,
        "[1,2,3]",
    );
}

// ── pcall with builtins ───────────────────────────────────────────────────────

#[test]
fn pcall_catches_builtin_error() {
    assert_returns_true(
        r#"
local ok, err = pcall(function() string.find("x", "^") end)
return ok == false
"#,
    );
}

#[test]
fn pcall_builtin_success() {
    assert_returns_str(
        r#"
local ok, result = pcall(function() return string.upper("hello") end)
return result
"#,
        "HELLO",
    );
}

// ── gas is charged for string operations ─────────────────────────────────────

#[test]
fn gas_charged_for_string_upper() {
    let out = run_ok(r#"return string.upper("hello")"#);
    // At minimum, base instruction + call + string.upper gas for 5 bytes
    assert!(out.gas_used > 5);
}

// ── comprehensive stdlib program ──────────────────────────────────────────────

#[test]
fn stdlib_comprehensive_program() {
    let out = run_ok(
        r#"
-- Use several stdlib functions together
local nums = {5, 3, 8, 1, 9, 2}
table.sort(nums)

local parts = {}
for i = 1, #nums do
    table.insert(parts, tostring(nums[i]))
end

local result = table.concat(parts, ",")
return result
"#,
    );
    assert_eq!(out.return_value, s("1,2,3,5,8,9"));
}

#[test]
fn stdlib_json_log_program() {
    let out = run_ok(
        r#"
local data = {name = "test", value = 42}
local encoded = json.encode(data)
log(encoded)
return string.len(encoded)
"#,
    );
    assert_eq!(out.logs.len(), 1);
    assert!(matches!(out.return_value, LuaValue::Integer(n) if n > 0));
}

// ── Regression: unsupported format spec must not panic ────────────────────────

#[test]
fn string_format_unsupported_spec_with_many_locals_returns_error() {
    // string.format with %04d (unsupported width specifier) after complex
    // control flow must return a runtime error, not panic on LoadLocal.
    let result = run(r#"
local timestamp = 1709654400
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
"#);
    assert!(result.is_err());
}
