//! Standard library builtin functions for the Lua VM.
//!
//! All builtins are dispatched through [`call_builtin`]. Gas and memory are
//! metered via the passed-in [`GasMeter`] and [`MemoryMeter`].

#[cfg(feature = "std")]
use std::{cell::RefCell, rc::Rc};
#[cfg(not(feature = "std"))]
use {
    alloc::{
        format,
        rc::Rc,
        string::{String, ToString},
        vec,
        vec::Vec,
    },
    core::cell::RefCell,
};

use crate::{
    types::{
        table::{LuaKey, LuaTable},
        value::{BuiltinId, LuaString, LuaValue},
    },
    vm::{
        gas::{VmError, gas_cost},
        memory::{MemoryMeter, alloc_size},
    },
};

use super::gas::GasMeter;

pub const MAX_STRING_LEN: usize = 65536; // 64 KB
pub const MAX_TABLE_DEPTH: usize = 32;

// ── Entry point ───────────────────────────────────────────────────────────────

/// Dispatch a builtin call. Returns a `Vec` of return values (0 or more).
/// The engine splats them onto the operand stack according to `expected_returns`.
///
/// `table_sort` is NOT handled here — it requires re-entrant VM dispatch and
/// is implemented as a method on `Vm` in `engine.rs`.
pub fn call_builtin(
    id: BuiltinId,
    args: &[LuaValue],
    gas: &mut GasMeter,
    mem: &mut MemoryMeter,
    _logs: &mut Vec<String>,
) -> Result<Vec<LuaValue>, VmError> {
    match id {
        // ── Core ──────────────────────────────────────────────────────────────
        BuiltinId::Type => builtin_type(args),
        BuiltinId::Tostring => builtin_tostring(args),
        BuiltinId::Tonumber => builtin_tonumber(args),
        BuiltinId::Select => builtin_select(args, gas),
        BuiltinId::Unpack => builtin_unpack(args, gas),

        // ── string ────────────────────────────────────────────────────────────
        BuiltinId::StringLen => string_len(args),
        BuiltinId::StringSub => string_sub(args, gas, mem),
        BuiltinId::StringFind => string_find(args, gas),
        BuiltinId::StringFindLiteral => string_find_literal(args, gas),
        BuiltinId::StringUpper => string_upper(args, gas, mem),
        BuiltinId::StringLower => string_lower(args, gas, mem),
        BuiltinId::StringRep => string_rep(args, gas, mem),
        BuiltinId::StringByte => string_byte(args, gas),
        BuiltinId::StringChar => string_char(args, gas, mem),
        BuiltinId::StringFormat => string_format(args, gas, mem),
        BuiltinId::StringUnsupported => Err(VmError::RuntimeError(LuaValue::String(
            LuaString::from_str("string.match/gmatch/gsub not supported"),
        ))),

        // ── math ──────────────────────────────────────────────────────────────
        BuiltinId::MathAbs => math_abs(args),
        BuiltinId::MathMin => math_min(args),
        BuiltinId::MathMax => math_max(args),
        BuiltinId::MathScaleDiv => math_scale_div(args),

        // ── table ─────────────────────────────────────────────────────────────
        BuiltinId::TableInsert => table_insert(args, gas, mem),
        BuiltinId::TableRemove => table_remove(args, gas),
        BuiltinId::TableConcat => table_concat(args, gas, mem),
        BuiltinId::TableMove => table_move(args, gas),
        // TableSort is handled in engine.rs (needs re-entrant dispatch)
        BuiltinId::TableSort => Err(VmError::RuntimeError(LuaValue::String(
            LuaString::from_str("table.sort must be dispatched by engine"),
        ))),

        // ── json ──────────────────────────────────────────────────────────────
        BuiltinId::JsonEncode => json_encode(args, gas, mem),
        BuiltinId::JsonDecode => json_decode(args, gas, mem),
        // log/error are handled as dedicated opcodes; if somehow called as builtins,
        // treat log here for consistency.
    }
    // Note: log and error have their own dedicated opcodes (Instruction::Log /
    // Instruction::Error) and are NOT routed through call_builtin.  The compiler
    // emits those opcodes directly when it recognises `log(...)` / `error(...)`.
    // The `logs` parameter is only passed in to make the signature consistent for
    // possible future use.
}

/// Dispatch a `log` call (separate because it mutates logs and has special gas).
pub fn call_log(
    args: &[LuaValue],
    gas: &mut GasMeter,
    mem: &mut MemoryMeter,
    logs: &mut Vec<String>,
) -> Result<Vec<LuaValue>, VmError> {
    let msg = require_string(args, 0, "log")?;
    let s = String::from_utf8_lossy(msg.as_bytes()).into_owned();
    gas.charge(gas_cost::LOG_BASE + s.len() as u64)?;
    mem.track_alloc(alloc_size::string(s.len()))?;
    logs.push(s);
    Ok(vec![])
}

// ── Helper macro/fns ─────────────────────────────────────────────────────────

fn require_arg<'a>(args: &'a [LuaValue], idx: usize, fname: &str) -> Result<&'a LuaValue, VmError> {
    args.get(idx).ok_or_else(|| {
        VmError::RuntimeError(LuaValue::String(LuaString::from_str(&format!(
            "{}: missing argument {}",
            fname,
            idx + 1
        ))))
    })
}

fn require_integer(args: &[LuaValue], idx: usize, fname: &str) -> Result<i64, VmError> {
    match require_arg(args, idx, fname)? {
        LuaValue::Integer(n) => Ok(*n),
        other => Err(VmError::TypeError(format!(
            "{}: expected integer, got {}",
            fname,
            other.type_name()
        ))),
    }
}

fn require_string<'a>(
    args: &'a [LuaValue],
    idx: usize,
    fname: &str,
) -> Result<&'a LuaString, VmError> {
    match require_arg(args, idx, fname)? {
        LuaValue::String(s) => Ok(s),
        other => Err(VmError::TypeError(format!(
            "{}: expected string, got {}",
            fname,
            other.type_name()
        ))),
    }
}

fn require_table(
    args: &[LuaValue],
    idx: usize,
    fname: &str,
) -> Result<Rc<RefCell<LuaTable>>, VmError> {
    match require_arg(args, idx, fname)? {
        LuaValue::Table(t) => Ok(Rc::clone(&t)),
        other => Err(VmError::TypeError(format!(
            "{}: expected table, got {}",
            fname,
            other.type_name()
        ))),
    }
}

fn runtime_err(msg: &str) -> VmError {
    VmError::RuntimeError(LuaValue::String(LuaString::from_str(msg)))
}

fn check_string_len(len: usize) -> Result<(), VmError> {
    if len > MAX_STRING_LEN {
        Err(runtime_err("string length overflow"))
    } else {
        Ok(())
    }
}

/// Convert a Lua 1-based (possibly negative) index to a 0-based byte offset
/// suitable as the *start* of a slice. Result is clamped to 0..=len.
fn lua_str_idx(i: i64, len: usize) -> usize {
    if i >= 0 {
        // Positive: 1-based → 0-based. i=0 treated same as i=1 (before first char).
        (i as usize).saturating_sub(1).min(len)
    } else {
        // Negative: -1 = last char, -2 = second to last, etc.
        let abs = (-i) as usize;
        if abs > len { 0 } else { len - abs }
    }
}

// ── Core builtins ─────────────────────────────────────────────────────────────

fn builtin_type(args: &[LuaValue]) -> Result<Vec<LuaValue>, VmError> {
    let v = require_arg(args, 0, "type")?;
    Ok(vec![LuaValue::String(LuaString::from_str(v.type_name()))])
}

fn builtin_tostring(args: &[LuaValue]) -> Result<Vec<LuaValue>, VmError> {
    let v = require_arg(args, 0, "tostring")?;
    Ok(vec![LuaValue::String(v.to_lua_string())])
}

fn builtin_tonumber(args: &[LuaValue]) -> Result<Vec<LuaValue>, VmError> {
    let v = require_arg(args, 0, "tonumber")?;
    let result = match v {
        LuaValue::Integer(_) => v.clone(),
        LuaValue::String(s) => {
            let trimmed = String::from_utf8_lossy(s.as_bytes());
            let trimmed = trimmed.trim();
            match trimmed.parse::<i64>() {
                Ok(n) => LuaValue::Integer(n),
                Err(_) => LuaValue::Nil,
            }
        }
        _ => LuaValue::Nil,
    };
    Ok(vec![result])
}

fn builtin_select(args: &[LuaValue], gas: &mut GasMeter) -> Result<Vec<LuaValue>, VmError> {
    gas.charge(gas_cost::BASE_INSTRUCTION)?;
    let index = require_arg(args, 0, "select")?;
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    match index {
        LuaValue::String(s) if s.as_bytes() == b"#" => {
            Ok(vec![LuaValue::Integer(rest.len() as i64)])
        }
        LuaValue::Integer(n) => {
            let n = *n;
            let len = rest.len() as i64;
            let idx = if n < 0 { len + n } else { n - 1 };
            if idx < 0 || idx >= len {
                return Err(VmError::RuntimeError(LuaValue::String(
                    LuaString::from_str("bad argument #1 to 'select' (index out of range)"),
                )));
            }
            Ok(vec![rest[idx as usize].clone()])
        }
        other => Err(VmError::TypeError(format!(
            "select: expected integer or '#', got {}",
            other.type_name()
        ))),
    }
}

fn builtin_unpack(args: &[LuaValue], gas: &mut GasMeter) -> Result<Vec<LuaValue>, VmError> {
    let t = require_table(args, 0, "unpack")?;
    let len = t.borrow().length();

    let i = if args.len() >= 2 {
        match &args[1] {
            LuaValue::Integer(n) => *n,
            other => {
                return Err(VmError::TypeError(format!(
                    "unpack: expected integer for i, got {}",
                    other.type_name()
                )));
            }
        }
    } else {
        1
    };

    let j = if args.len() >= 3 {
        match &args[2] {
            LuaValue::Integer(n) => *n,
            other => {
                return Err(VmError::TypeError(format!(
                    "unpack: expected integer for j, got {}",
                    other.type_name()
                )));
            }
        }
    } else {
        len
    };

    if i > j {
        return Ok(vec![]);
    }

    let count = (j - i + 1) as u64;
    gas.charge(1 + count * 2)?;

    let mut result = Vec::with_capacity(count as usize);
    for k in i..=j {
        let val = t
            .borrow()
            .get(&LuaKey::Integer(k))
            .cloned()
            .unwrap_or(LuaValue::Nil);
        result.push(val);
    }
    Ok(result)
}

// ── string module ─────────────────────────────────────────────────────────────

fn string_len(args: &[LuaValue]) -> Result<Vec<LuaValue>, VmError> {
    let s = require_string(args, 0, "string.len")?;
    Ok(vec![LuaValue::Integer(s.len() as i64)])
}

fn string_sub(
    args: &[LuaValue],
    gas: &mut GasMeter,
    mem: &mut MemoryMeter,
) -> Result<Vec<LuaValue>, VmError> {
    let s = require_string(args, 0, "string.sub")?;
    let len = s.len();
    let i_raw = require_integer(args, 1, "string.sub")?;
    let j_raw = if args.len() >= 3 {
        match &args[2] {
            LuaValue::Integer(n) => *n,
            other => {
                return Err(VmError::TypeError(format!(
                    "string.sub: expected integer for j, got {}",
                    other.type_name()
                )));
            }
        }
    } else {
        len as i64
    };

    let start = lua_str_idx(i_raw, len);
    // end is the exclusive byte boundary for the slice.
    // For positive j: end = min(j, len)
    // For negative j: end = len - abs + 1  (where abs = -j)
    let end = if j_raw >= 0 {
        (j_raw as usize).min(len)
    } else {
        let abs = (-j_raw) as usize;
        if abs > len { 0 } else { len - abs + 1 }
    };

    if start >= end {
        return Ok(vec![LuaValue::String(LuaString::from_str(""))]);
    }

    let bytes_copied = end - start;
    gas.charge(bytes_copied as u64)?;
    mem.track_alloc(alloc_size::string(bytes_copied))?;

    let result = LuaString::from_bytes(&s.as_bytes()[start..end]);
    Ok(vec![LuaValue::String(result)])
}

/// Check for Lua pattern metacharacters; error if found.
fn check_no_pattern_metachar(pattern: &[u8]) -> Result<(), VmError> {
    for &b in pattern {
        if matches!(
            b,
            b'^' | b'$' | b'(' | b')' | b'%' | b'.' | b'[' | b']' | b'*' | b'+' | b'-' | b'?'
        ) {
            return Err(runtime_err(
                "string patterns not supported; use literal string.find only",
            ));
        }
    }
    Ok(())
}

/// Resolve the optional `init` argument shared by `string.find` and
/// `string.find_literal`: 1-based, clamped at 1, converted to a 0-based offset.
fn parse_find_init(args: &[LuaValue], fn_name: &str) -> Result<usize, VmError> {
    if args.len() < 3 {
        return Ok(0);
    }
    let n = match &args[2] {
        LuaValue::Integer(n) => *n,
        other => {
            return Err(VmError::TypeError(format!(
                "{fn_name}: expected integer for init, got {}",
                other.type_name()
            )));
        }
    };
    Ok(if n < 1 { 0 } else { (n - 1) as usize })
}

/// Literal byte-substring search shared by `string.find` (after its metachar
/// check) and `string.find_literal` (which skips the check). Returns the
/// 1-based inclusive [start, end] pair, or `(nil, nil)` if not found.
fn literal_substring_search(
    haystack: &[u8],
    needle: &[u8],
    init: usize,
    gas: &mut GasMeter,
) -> Result<Vec<LuaValue>, VmError> {
    gas.charge(haystack.len() as u64)?;

    if needle.is_empty() {
        let pos = init.min(haystack.len());
        return Ok(vec![
            LuaValue::Integer((pos + 1) as i64),
            LuaValue::Integer(pos as i64),
        ]);
    }

    if init > haystack.len() {
        return Ok(vec![LuaValue::Nil, LuaValue::Nil]);
    }

    let search_space = &haystack[init..];
    let found = search_space.windows(needle.len()).position(|w| w == needle);

    match found {
        Some(offset) => {
            let abs = init + offset;
            Ok(vec![
                LuaValue::Integer((abs + 1) as i64),
                LuaValue::Integer((abs + needle.len()) as i64),
            ])
        }
        None => Ok(vec![LuaValue::Nil, LuaValue::Nil]),
    }
}

fn string_find(args: &[LuaValue], gas: &mut GasMeter) -> Result<Vec<LuaValue>, VmError> {
    let s = require_string(args, 0, "string.find")?;
    let pat = require_string(args, 1, "string.find")?;
    let init = parse_find_init(args, "string.find")?;
    check_no_pattern_metachar(pat.as_bytes())?;
    literal_substring_search(s.as_bytes(), pat.as_bytes(), init, gas)
}

/// `string.find_literal(s, needle [, init])` — like `string.find` but treats
/// every byte of `needle` as a literal, so callers can search for substrings
/// containing pattern metacharacters (`.`, `*`, `+`, `?`, `^`, `$`, `(`, `)`,
/// `%`, `[`, `]`, `-`) without first escaping them.
fn string_find_literal(args: &[LuaValue], gas: &mut GasMeter) -> Result<Vec<LuaValue>, VmError> {
    let s = require_string(args, 0, "string.find_literal")?;
    let needle = require_string(args, 1, "string.find_literal")?;
    let init = parse_find_init(args, "string.find_literal")?;
    literal_substring_search(s.as_bytes(), needle.as_bytes(), init, gas)
}

fn string_upper(
    args: &[LuaValue],
    gas: &mut GasMeter,
    mem: &mut MemoryMeter,
) -> Result<Vec<LuaValue>, VmError> {
    let s = require_string(args, 0, "string.upper")?;
    gas.charge(s.len() as u64)?;
    mem.track_alloc(alloc_size::string(s.len()))?;
    let result: Vec<u8> = s
        .as_bytes()
        .iter()
        .map(|b| b.to_ascii_uppercase())
        .collect();
    Ok(vec![LuaValue::String(LuaString::from_bytes(&result))])
}

fn string_lower(
    args: &[LuaValue],
    gas: &mut GasMeter,
    mem: &mut MemoryMeter,
) -> Result<Vec<LuaValue>, VmError> {
    let s = require_string(args, 0, "string.lower")?;
    gas.charge(s.len() as u64)?;
    mem.track_alloc(alloc_size::string(s.len()))?;
    let result: Vec<u8> = s
        .as_bytes()
        .iter()
        .map(|b| b.to_ascii_lowercase())
        .collect();
    Ok(vec![LuaValue::String(LuaString::from_bytes(&result))])
}

fn string_rep(
    args: &[LuaValue],
    gas: &mut GasMeter,
    mem: &mut MemoryMeter,
) -> Result<Vec<LuaValue>, VmError> {
    let s = require_string(args, 0, "string.rep")?;
    let n = require_integer(args, 1, "string.rep")?;

    if n <= 0 {
        return Ok(vec![LuaValue::String(LuaString::from_str(""))]);
    }

    let n = n as usize;
    let result_len = s.len().saturating_mul(n);
    check_string_len(result_len)?;
    gas.charge((s.len() * n) as u64)?;
    mem.track_alloc(alloc_size::string(result_len))?;

    let mut buf = Vec::with_capacity(result_len);
    for _ in 0..n {
        buf.extend_from_slice(s.as_bytes());
    }
    Ok(vec![LuaValue::String(LuaString::from_bytes(&buf))])
}

fn string_byte(args: &[LuaValue], gas: &mut GasMeter) -> Result<Vec<LuaValue>, VmError> {
    let s = require_string(args, 0, "string.byte")?;
    let len = s.len();

    let i_raw = if args.len() >= 2 {
        require_integer(args, 1, "string.byte")?
    } else {
        1
    };
    let j_raw = if args.len() >= 3 {
        match &args[2] {
            LuaValue::Integer(n) => *n,
            _ => i_raw,
        }
    } else {
        i_raw
    };

    let start = lua_str_idx(i_raw, len);
    let end = if j_raw >= 0 {
        (j_raw as usize).min(len)
    } else {
        let abs = (-j_raw) as usize;
        if abs > len { 0 } else { len - abs + 1 }
    };

    if start >= end {
        return Ok(vec![]);
    }

    let count = (end - start) as u64;
    gas.charge(count)?;

    let result: Vec<LuaValue> = s.as_bytes()[start..end]
        .iter()
        .map(|&b| LuaValue::Integer(b as i64))
        .collect();
    Ok(result)
}

fn string_char(
    args: &[LuaValue],
    gas: &mut GasMeter,
    mem: &mut MemoryMeter,
) -> Result<Vec<LuaValue>, VmError> {
    gas.charge(args.len() as u64)?;
    mem.track_alloc(alloc_size::string(args.len()))?;

    let mut buf = Vec::with_capacity(args.len());
    for (i, arg) in args.iter().enumerate() {
        match arg {
            LuaValue::Integer(n) => {
                if *n < 0 || *n > 255 {
                    return Err(VmError::TypeError(format!(
                        "string.char: argument {} out of range ({})",
                        i + 1,
                        n
                    )));
                }
                buf.push(*n as u8);
            }
            other => {
                return Err(VmError::TypeError(format!(
                    "string.char: expected integer, got {}",
                    other.type_name()
                )));
            }
        }
    }
    Ok(vec![LuaValue::String(LuaString::from_bytes(&buf))])
}

fn string_format(
    args: &[LuaValue],
    gas: &mut GasMeter,
    mem: &mut MemoryMeter,
) -> Result<Vec<LuaValue>, VmError> {
    let fmt = require_string(args, 0, "string.format")?;
    let fmt_bytes = fmt.as_bytes().to_vec();

    let mut result = Vec::<u8>::new();
    let mut arg_idx = 1usize;
    let mut i = 0usize;

    while i < fmt_bytes.len() {
        if fmt_bytes[i] != b'%' {
            result.push(fmt_bytes[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= fmt_bytes.len() {
            return Err(runtime_err("string.format: trailing % in format string"));
        }
        match fmt_bytes[i] {
            b'%' => {
                result.push(b'%');
                i += 1;
            }
            b'd' => {
                let n = require_integer(args, arg_idx, "string.format")?;
                arg_idx += 1;
                let s = n.to_string();
                result.extend_from_slice(s.as_bytes());
                i += 1;
            }
            b's' => {
                let v = require_arg(args, arg_idx, "string.format")?;
                arg_idx += 1;
                let s = v.to_lua_string();
                result.extend_from_slice(s.as_bytes());
                i += 1;
            }
            b'x' => {
                let n = require_integer(args, arg_idx, "string.format")?;
                arg_idx += 1;
                let s = if n < 0 {
                    // Treat as unsigned 64-bit
                    format!("{:x}", n as u64)
                } else {
                    format!("{:x}", n)
                };
                result.extend_from_slice(s.as_bytes());
                i += 1;
            }
            b'0'..=b'9' | b'-' | b'.' | b'*' => {
                return Err(runtime_err(
                    "string.format: width/precision specifiers not supported in v0.2",
                ));
            }
            other => {
                return Err(VmError::RuntimeError(LuaValue::String(
                    LuaString::from_str(&format!(
                        "string.format: unsupported format specifier '%{}'",
                        other as char
                    )),
                )));
            }
        }
    }

    check_string_len(result.len())?;
    gas.charge(result.len() as u64)?;
    mem.track_alloc(alloc_size::string(result.len()))?;

    Ok(vec![LuaValue::String(LuaString::from_bytes(&result))])
}

// ── math module ───────────────────────────────────────────────────────────────

fn math_abs(args: &[LuaValue]) -> Result<Vec<LuaValue>, VmError> {
    let n = require_integer(args, 0, "math.abs")?;
    Ok(vec![LuaValue::Integer(n.wrapping_abs())])
}

fn math_min(args: &[LuaValue]) -> Result<Vec<LuaValue>, VmError> {
    if args.is_empty() {
        return Err(runtime_err("math.min: at least one argument required"));
    }
    let mut result = require_integer(args, 0, "math.min")?;
    for (i, arg) in args.iter().enumerate().skip(1) {
        let n = match arg {
            LuaValue::Integer(n) => *n,
            other => {
                return Err(VmError::TypeError(format!(
                    "math.min: expected integer, got {}",
                    other.type_name()
                )));
            }
        };
        if n < result {
            result = n;
        }
        let _ = i;
    }
    Ok(vec![LuaValue::Integer(result)])
}

fn math_max(args: &[LuaValue]) -> Result<Vec<LuaValue>, VmError> {
    if args.is_empty() {
        return Err(runtime_err("math.max: at least one argument required"));
    }
    let mut result = require_integer(args, 0, "math.max")?;
    for arg in args.iter().skip(1) {
        let n = match arg {
            LuaValue::Integer(n) => *n,
            other => {
                return Err(VmError::TypeError(format!(
                    "math.max: expected integer, got {}",
                    other.type_name()
                )));
            }
        };
        if n > result {
            result = n;
        }
    }
    Ok(vec![LuaValue::Integer(result)])
}

fn math_scale_div(args: &[LuaValue]) -> Result<Vec<LuaValue>, VmError> {
    let a = require_integer(args, 0, "math.scale_div")?;
    let b = require_integer(args, 1, "math.scale_div")?;
    let scale = require_integer(args, 2, "math.scale_div")?;

    if b == 0 {
        return Err(runtime_err("math.scale_div: division by zero"));
    }

    let result = (a as i128 * scale as i128) / (b as i128);
    if result > i64::MAX as i128 || result < i64::MIN as i128 {
        return Err(runtime_err("math.scale_div: overflow"));
    }

    Ok(vec![LuaValue::Integer(result as i64)])
}

// ── table module ──────────────────────────────────────────────────────────────

fn table_insert(
    args: &[LuaValue],
    gas: &mut GasMeter,
    mem: &mut MemoryMeter,
) -> Result<Vec<LuaValue>, VmError> {
    // table.insert(t, value)  OR  table.insert(t, pos, value)
    let t = require_table(args, 0, "table.insert")?;

    let (pos, value) = if args.len() >= 3 {
        let p = require_integer(args, 1, "table.insert")?;
        (p, args[2].clone())
    } else if args.len() == 2 {
        let len = t.borrow().length();
        (len + 1, args[1].clone())
    } else {
        return Err(runtime_err("table.insert: missing value argument"));
    };

    let len = t.borrow().length();
    if pos < 1 || pos > len + 1 {
        return Err(runtime_err("table.insert: position out of range"));
    }

    // Shift elements right from pos..=len.
    let shift_count = (len - pos + 1).max(0) as u64;
    gas.charge(5 + shift_count)?;

    // Move elements len down to pos upward by one.
    for k in (pos..=len).rev() {
        let v = t
            .borrow()
            .get(&LuaKey::Integer(k))
            .cloned()
            .unwrap_or(LuaValue::Nil);
        let old_cap = t.borrow().capacity();
        let result = t
            .borrow_mut()
            .rawset_tracked(LuaKey::Integer(k + 1), v)
            .map_err(|e| VmError::from(e))?;
        charge_rawset_result(result, old_cap, &t, mem)?;
    }

    // Insert.
    let old_cap = t.borrow().capacity();
    let result = t
        .borrow_mut()
        .rawset_tracked(LuaKey::Integer(pos), value)
        .map_err(|e| VmError::from(e))?;
    charge_rawset_result(result, old_cap, &t, mem)?;

    Ok(vec![])
}

fn table_remove(args: &[LuaValue], gas: &mut GasMeter) -> Result<Vec<LuaValue>, VmError> {
    let t = require_table(args, 0, "table.remove")?;
    let len = t.borrow().length();

    if len == 0 {
        return Ok(vec![LuaValue::Nil]);
    }

    let pos = if args.len() >= 2 {
        require_integer(args, 1, "table.remove")?
    } else {
        len
    };

    if pos < 1 || pos > len {
        return Err(runtime_err("table.remove: position out of range"));
    }

    let removed = t
        .borrow()
        .get(&LuaKey::Integer(pos))
        .cloned()
        .unwrap_or(LuaValue::Nil);

    // Shift elements left.
    let shift_count = (len - pos) as u64;
    gas.charge(5 + shift_count)?;

    for k in pos..len {
        let v = t
            .borrow()
            .get(&LuaKey::Integer(k + 1))
            .cloned()
            .unwrap_or(LuaValue::Nil);
        t.borrow_mut()
            .rawset(LuaKey::Integer(k), v)
            .map_err(|e| VmError::from(e))?;
    }

    // Remove last slot.
    t.borrow_mut().rawremove(&LuaKey::Integer(len));

    Ok(vec![removed])
}

fn table_concat(
    args: &[LuaValue],
    gas: &mut GasMeter,
    mem: &mut MemoryMeter,
) -> Result<Vec<LuaValue>, VmError> {
    let t = require_table(args, 0, "table.concat")?;
    let len = t.borrow().length();

    let sep: Vec<u8> = if args.len() >= 2 {
        match &args[1] {
            LuaValue::String(s) => s.as_bytes().to_vec(),
            LuaValue::Nil => vec![],
            other => {
                return Err(VmError::TypeError(format!(
                    "table.concat: expected string sep, got {}",
                    other.type_name()
                )));
            }
        }
    } else {
        vec![]
    };

    let i = if args.len() >= 3 {
        require_integer(args, 2, "table.concat")?
    } else {
        1
    };

    let j = if args.len() >= 4 {
        require_integer(args, 3, "table.concat")?
    } else {
        len
    };

    if i > j {
        return Ok(vec![LuaValue::String(LuaString::from_str(""))]);
    }

    let mut parts: Vec<Vec<u8>> = Vec::new();
    for k in i..=j {
        let v = t
            .borrow()
            .get(&LuaKey::Integer(k))
            .cloned()
            .unwrap_or(LuaValue::Nil);
        match v {
            LuaValue::String(s) => parts.push(s.as_bytes().to_vec()),
            LuaValue::Integer(n) => parts.push(n.to_string().into_bytes()),
            _ => {
                return Err(runtime_err(&format!(
                    "table.concat: element at index {} is not a string or number",
                    k
                )));
            }
        }
    }

    let result_len =
        parts.iter().map(|p| p.len()).sum::<usize>() + sep.len() * parts.len().saturating_sub(1);
    check_string_len(result_len)?;
    gas.charge(result_len as u64)?;
    mem.track_alloc(alloc_size::string(result_len))?;

    let mut buf = Vec::with_capacity(result_len);
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            buf.extend_from_slice(&sep);
        }
        buf.extend_from_slice(part);
    }

    Ok(vec![LuaValue::String(LuaString::from_bytes(&buf))])
}

fn table_move(args: &[LuaValue], gas: &mut GasMeter) -> Result<Vec<LuaValue>, VmError> {
    let a = require_table(args, 0, "table.move")?;
    let f = require_integer(args, 1, "table.move")?;
    let e = require_integer(args, 2, "table.move")?;
    let t_pos = require_integer(args, 3, "table.move")?;

    let a2 = if args.len() >= 5 {
        require_table(args, 4, "table.move")?
    } else {
        Rc::clone(&a)
    };

    if f > e {
        if args.len() >= 5 {
            return Ok(vec![LuaValue::Table(a2)]);
        }
        return Ok(vec![]);
    }

    let count = (e - f + 1) as u64;
    gas.charge(count)?;

    // Collect values first to handle overlapping case.
    let values: Vec<LuaValue> = (f..=e)
        .map(|k| {
            a.borrow()
                .get(&LuaKey::Integer(k))
                .cloned()
                .unwrap_or(LuaValue::Nil)
        })
        .collect();

    for (idx, v) in values.into_iter().enumerate() {
        let dest_k = t_pos + idx as i64;
        a2.borrow_mut()
            .rawset(LuaKey::Integer(dest_k), v)
            .map_err(|e| VmError::from(e))?;
    }

    if args.len() >= 5 {
        Ok(vec![LuaValue::Table(a2)])
    } else {
        Ok(vec![])
    }
}

/// Merge-sort the array portion of a table in-place using a comparison function
/// expressed as a Rust closure (the engine provides the actual comparator).
///
/// `compare(a, b)` should return `Ok(true)` if `a < b`.
pub fn merge_sort_table<F>(
    t: &Rc<RefCell<LuaTable>>,
    gas: &mut GasMeter,
    n: usize,
    mut compare: F,
) -> Result<(), VmError>
where
    F: FnMut(&LuaValue, &LuaValue) -> Result<bool, VmError>,
{
    if n <= 1 {
        return Ok(());
    }

    // Charge gas: n * ceil_log2(n + 1)
    let sort_gas = n as u64 * ceil_log2(n + 1);
    gas.charge(sort_gas)?;

    // Extract array into a Vec.
    let mut arr: Vec<LuaValue> = (1..=n as i64)
        .map(|k| {
            t.borrow()
                .get(&LuaKey::Integer(k))
                .cloned()
                .unwrap_or(LuaValue::Nil)
        })
        .collect();

    // Merge sort.
    merge_sort_slice(&mut arr, &mut compare)?;

    // Write back.
    for (i, v) in arr.into_iter().enumerate() {
        t.borrow_mut()
            .rawset(LuaKey::Integer((i + 1) as i64), v)
            .map_err(|e| VmError::from(e))?;
    }

    Ok(())
}

fn merge_sort_slice<F>(arr: &mut Vec<LuaValue>, compare: &mut F) -> Result<(), VmError>
where
    F: FnMut(&LuaValue, &LuaValue) -> Result<bool, VmError>,
{
    let n = arr.len();
    if n <= 1 {
        return Ok(());
    }

    let mid = n / 2;
    let mut left = arr[..mid].to_vec();
    let mut right = arr[mid..].to_vec();

    merge_sort_slice(&mut left, compare)?;
    merge_sort_slice(&mut right, compare)?;

    // Merge.
    let mut i = 0;
    let mut j = 0;
    let mut k = 0;
    while i < left.len() && j < right.len() {
        if compare(&left[i], &right[j])? {
            arr[k] = left[i].clone();
            i += 1;
        } else {
            arr[k] = right[j].clone();
            j += 1;
        }
        k += 1;
    }
    while i < left.len() {
        arr[k] = left[i].clone();
        i += 1;
        k += 1;
    }
    while j < right.len() {
        arr[k] = right[j].clone();
        j += 1;
        k += 1;
    }
    Ok(())
}

// ── JSON module ───────────────────────────────────────────────────────────────

fn json_encode(
    args: &[LuaValue],
    gas: &mut GasMeter,
    mem: &mut MemoryMeter,
) -> Result<Vec<LuaValue>, VmError> {
    let v = require_arg(args, 0, "json.encode")?;
    let result = crate::host::canonicalize::canonical_serialize(v).map_err(VmError::from)?;
    check_string_len(result.len())?;
    gas.charge(result.len() as u64)?;
    mem.track_alloc(alloc_size::string(result.len()))?;
    Ok(vec![LuaValue::String(LuaString::from_bytes(&result))])
}

fn json_decode(
    args: &[LuaValue],
    gas: &mut GasMeter,
    mem: &mut MemoryMeter,
) -> Result<Vec<LuaValue>, VmError> {
    let s = require_string(args, 0, "json.decode")?;
    let input = s.as_bytes();
    gas.charge(input.len() as u64)?;
    let (val, end) = json_parse(input, 0, mem)?;
    if end != input.len() {
        return Err(runtime_err(&format!(
            "json.decode: trailing characters at position {end}"
        )));
    }
    Ok(vec![val])
}

struct JsonParser<'a> {
    input: &'a [u8],
    pos: usize,
    depth: usize,
    mem: &'a mut MemoryMeter,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a [u8], mem: &'a mut MemoryMeter) -> Self {
        JsonParser {
            input,
            pos: 0,
            depth: 0,
            mem,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), VmError> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(runtime_err(&format!(
                "json.decode: expected '{}' at position {}",
                b as char, self.pos
            )))
        }
    }

    fn parse_value(&mut self) -> Result<LuaValue, VmError> {
        if self.depth > MAX_TABLE_DEPTH {
            return Err(runtime_err("json.decode: nesting depth exceeded"));
        }
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.parse_string(),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b't') => {
                self.expect_lit(b"true")?;
                Ok(LuaValue::Boolean(true))
            }
            Some(b'f') => {
                self.expect_lit(b"false")?;
                Ok(LuaValue::Boolean(false))
            }
            Some(b'n') => {
                self.expect_lit(b"null")?;
                Ok(LuaValue::Nil)
            }
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(b) => Err(runtime_err(&format!(
                "json.decode: unexpected character '{}' at position {}",
                b as char, self.pos
            ))),
            None => Err(runtime_err("json.decode: unexpected end of input")),
        }
    }

    fn expect_lit(&mut self, lit: &[u8]) -> Result<(), VmError> {
        if self.input.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(runtime_err(&format!(
                "json.decode: expected '{}' at position {}",
                String::from_utf8_lossy(lit),
                self.pos
            )))
        }
    }

    fn parse_string(&mut self) -> Result<LuaValue, VmError> {
        self.expect(b'"')?;
        let mut buf = Vec::new();
        loop {
            match self.peek() {
                None => return Err(runtime_err("json.decode: unterminated string")),
                Some(b'"') => {
                    self.pos += 1;
                    break;
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'"') => {
                            buf.push(b'"');
                            self.pos += 1;
                        }
                        Some(b'\\') => {
                            buf.push(b'\\');
                            self.pos += 1;
                        }
                        Some(b'/') => {
                            buf.push(b'/');
                            self.pos += 1;
                        }
                        Some(b'n') => {
                            buf.push(b'\n');
                            self.pos += 1;
                        }
                        Some(b'r') => {
                            buf.push(b'\r');
                            self.pos += 1;
                        }
                        Some(b't') => {
                            buf.push(b'\t');
                            self.pos += 1;
                        }
                        Some(b'b') => {
                            buf.push(0x08);
                            self.pos += 1;
                        }
                        Some(b'f') => {
                            buf.push(0x0C);
                            self.pos += 1;
                        }
                        Some(b'u') => {
                            self.pos += 1;
                            if self.pos + 4 > self.input.len() {
                                return Err(runtime_err("json.decode: invalid \\u escape"));
                            }
                            let hex = &self.input[self.pos..self.pos + 4];
                            let s = core::str::from_utf8(hex)
                                .map_err(|_| runtime_err("json.decode: invalid \\u escape"))?;
                            let code = u32::from_str_radix(s, 16)
                                .map_err(|_| runtime_err("json.decode: invalid \\u escape"))?;
                            self.pos += 4;
                            // Encode as UTF-8 bytes.
                            let ch = char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER);
                            let mut tmp = [0u8; 4];
                            let encoded = ch.encode_utf8(&mut tmp);
                            buf.extend_from_slice(encoded.as_bytes());
                        }
                        _ => return Err(runtime_err("json.decode: invalid escape sequence")),
                    }
                }
                Some(b) => {
                    buf.push(b);
                    self.pos += 1;
                }
            }
        }
        self.mem
            .track_alloc(alloc_size::string(buf.len()))
            .map_err(|e| e)?;
        Ok(LuaValue::String(LuaString::from_bytes(&buf)))
    }

    fn parse_number(&mut self) -> Result<LuaValue, VmError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b'0'..=b'9') = self.peek() {
            self.pos += 1;
        }
        // Check for fractional/exponent (not supported).
        if self.peek() == Some(b'.') || self.peek() == Some(b'e') || self.peek() == Some(b'E') {
            return Err(runtime_err(
                "json.decode: fractional numbers not supported; only integers",
            ));
        }
        let s = core::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| runtime_err("json.decode: invalid number"))?;
        let n = s
            .parse::<i64>()
            .map_err(|_| runtime_err("json.decode: number out of i64 range"))?;
        Ok(LuaValue::Integer(n))
    }

    fn parse_array(&mut self) -> Result<LuaValue, VmError> {
        self.expect(b'[')?;
        self.depth += 1;

        let t = Rc::new(RefCell::new(LuaTable::new()));
        self.mem.track_alloc(alloc_size::table_base())?;

        let mut idx: i64 = 1;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(LuaValue::Table(t));
        }

        loop {
            let v = self.parse_value()?;
            let old_cap = t.borrow().capacity();
            let rs = t
                .borrow_mut()
                .rawset_tracked(LuaKey::Integer(idx), v)
                .map_err(|e| VmError::from(e))?;
            charge_rawset_result(rs, old_cap, &t, self.mem)?;
            idx += 1;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(runtime_err("json.decode: expected ',' or ']' in array")),
            }
        }

        self.depth -= 1;
        Ok(LuaValue::Table(t))
    }

    fn parse_object(&mut self) -> Result<LuaValue, VmError> {
        self.expect(b'{')?;
        self.depth += 1;

        let t = Rc::new(RefCell::new(LuaTable::new()));
        self.mem.track_alloc(alloc_size::table_base())?;

        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(LuaValue::Table(t));
        }

        loop {
            self.skip_ws();
            let key_val = self.parse_string()?;
            let key = match key_val {
                LuaValue::String(s) => LuaKey::String(s),
                _ => return Err(runtime_err("json.decode: object key must be string")),
            };
            self.skip_ws();
            self.expect(b':')?;
            let v = self.parse_value()?;
            let old_cap = t.borrow().capacity();
            let rs = t
                .borrow_mut()
                .rawset_tracked(key, v)
                .map_err(|e| VmError::from(e))?;
            charge_rawset_result(rs, old_cap, &t, self.mem)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(runtime_err("json.decode: expected ',' or '}' in object")),
            }
        }

        self.depth -= 1;
        Ok(LuaValue::Table(t))
    }
}

fn json_parse(
    input: &[u8],
    _start: usize,
    mem: &mut MemoryMeter,
) -> Result<(LuaValue, usize), VmError> {
    let mut parser = JsonParser::new(input, mem);
    let v = parser.parse_value()?;
    parser.skip_ws();
    Ok((v, parser.pos))
}

/// Parse canonical JSON bytes into a `LuaValue` without VM metering.
///
/// Used by `TapeHost` to decode pre-recorded tool responses from an
/// `OracleTape`. The resulting value is subject to normal VM resource
/// accounting once the host returns it to the engine.
pub fn decode_json_bytes(bytes: &[u8]) -> Result<LuaValue, String> {
    let mut mem = MemoryMeter::new(u64::MAX);
    json_parse(bytes, 0, &mut mem)
        .map(|(v, _)| v)
        .map_err(|e| format!("{e:?}"))
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn charge_rawset_result(
    result: crate::types::table::RawsetResult,
    old_cap: usize,
    t: &Rc<RefCell<LuaTable>>,
    mem: &mut MemoryMeter,
) -> Result<(), VmError> {
    use crate::types::table::RawsetResult;
    match result {
        RawsetResult::Updated => {}
        RawsetResult::Inserted {
            grew,
            new_hash_capacity,
        } => {
            if grew {
                let delta = new_hash_capacity.saturating_sub(old_cap) as u64;
                mem.track_alloc(delta * alloc_size::table_hash_slot())?;
            } else {
                mem.track_alloc(alloc_size::table_array_slot())?;
            }
        }
    }
    let _ = t;
    Ok(())
}

/// ceil(log2(n)), returning 0 for n <= 1.
pub fn ceil_log2(n: usize) -> u64 {
    if n <= 1 {
        return 0;
    }
    (usize::BITS - (n - 1).leading_zeros()) as u64
}

// ── Build the globals table ───────────────────────────────────────────────────

/// Build the initial globals table that the VM exposes for `LoadGlobal`/`PushK` sentinel lookups.
pub fn build_globals() -> LuaTable {
    let mut g = LuaTable::new();

    macro_rules! set_builtin {
        ($name:expr, $id:expr) => {
            g.rawset(
                LuaKey::String(LuaString::from_str($name)),
                LuaValue::Builtin($id),
            )
            .unwrap();
        };
    }

    // Core functions accessible by sentinel key __tostring etc.
    set_builtin!("__type", BuiltinId::Type);
    set_builtin!("__tostring", BuiltinId::Tostring);
    set_builtin!("__tonumber", BuiltinId::Tonumber);
    set_builtin!("__select", BuiltinId::Select);
    set_builtin!("__unpack", BuiltinId::Unpack);

    // Module tables.
    let string_mod = build_string_module();
    let math_mod = build_math_module();
    let table_mod = build_table_module();
    let json_mod = build_json_module();

    g.rawset(
        LuaKey::String(LuaString::from_str("__string")),
        LuaValue::Table(Rc::new(RefCell::new(string_mod))),
    )
    .unwrap();
    g.rawset(
        LuaKey::String(LuaString::from_str("__math")),
        LuaValue::Table(Rc::new(RefCell::new(math_mod))),
    )
    .unwrap();
    g.rawset(
        LuaKey::String(LuaString::from_str("__table")),
        LuaValue::Table(Rc::new(RefCell::new(table_mod))),
    )
    .unwrap();
    g.rawset(
        LuaKey::String(LuaString::from_str("__json")),
        LuaValue::Table(Rc::new(RefCell::new(json_mod))),
    )
    .unwrap();

    g
}

fn build_string_module() -> LuaTable {
    let mut t = LuaTable::new();
    macro_rules! sf {
        ($k:expr, $id:expr) => {
            t.rawset(
                LuaKey::String(LuaString::from_str($k)),
                LuaValue::Builtin($id),
            )
            .unwrap();
        };
    }
    sf!("len", BuiltinId::StringLen);
    sf!("sub", BuiltinId::StringSub);
    sf!("find", BuiltinId::StringFind);
    sf!("find_literal", BuiltinId::StringFindLiteral);
    sf!("upper", BuiltinId::StringUpper);
    sf!("lower", BuiltinId::StringLower);
    sf!("rep", BuiltinId::StringRep);
    sf!("byte", BuiltinId::StringByte);
    sf!("char", BuiltinId::StringChar);
    sf!("format", BuiltinId::StringFormat);
    sf!("match", BuiltinId::StringUnsupported);
    sf!("gmatch", BuiltinId::StringUnsupported);
    sf!("gsub", BuiltinId::StringUnsupported);
    t
}

fn build_math_module() -> LuaTable {
    let mut t = LuaTable::new();
    macro_rules! mf {
        ($k:expr, $id:expr) => {
            t.rawset(
                LuaKey::String(LuaString::from_str($k)),
                LuaValue::Builtin($id),
            )
            .unwrap();
        };
    }
    mf!("abs", BuiltinId::MathAbs);
    mf!("min", BuiltinId::MathMin);
    mf!("max", BuiltinId::MathMax);
    mf!("scale_div", BuiltinId::MathScaleDiv);
    t.rawset(
        LuaKey::String(LuaString::from_str("maxinteger")),
        LuaValue::Integer(i64::MAX),
    )
    .unwrap();
    t.rawset(
        LuaKey::String(LuaString::from_str("mininteger")),
        LuaValue::Integer(i64::MIN),
    )
    .unwrap();
    t
}

fn build_table_module() -> LuaTable {
    let mut t = LuaTable::new();
    macro_rules! tf {
        ($k:expr, $id:expr) => {
            t.rawset(
                LuaKey::String(LuaString::from_str($k)),
                LuaValue::Builtin($id),
            )
            .unwrap();
        };
    }
    tf!("insert", BuiltinId::TableInsert);
    tf!("remove", BuiltinId::TableRemove);
    tf!("concat", BuiltinId::TableConcat);
    tf!("sort", BuiltinId::TableSort);
    tf!("move", BuiltinId::TableMove);
    t
}

fn build_json_module() -> LuaTable {
    let mut t = LuaTable::new();
    t.rawset(
        LuaKey::String(LuaString::from_str("encode")),
        LuaValue::Builtin(BuiltinId::JsonEncode),
    )
    .unwrap();
    t.rawset(
        LuaKey::String(LuaString::from_str("decode")),
        LuaValue::Builtin(BuiltinId::JsonDecode),
    )
    .unwrap();
    t
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::gas::GasMeter;
    use crate::vm::memory::MemoryMeter;

    fn gas() -> GasMeter {
        GasMeter::new(1_000_000)
    }
    fn mem() -> MemoryMeter {
        MemoryMeter::new(16 * 1024 * 1024)
    }
    fn logs() -> Vec<String> {
        Vec::new()
    }

    fn int(n: i64) -> LuaValue {
        LuaValue::Integer(n)
    }
    fn s(text: &str) -> LuaValue {
        LuaValue::String(LuaString::from_str(text))
    }
    fn make_table() -> Rc<RefCell<LuaTable>> {
        Rc::new(RefCell::new(LuaTable::new()))
    }
    fn tval(t: Rc<RefCell<LuaTable>>) -> LuaValue {
        LuaValue::Table(t)
    }

    fn dispatch(id: BuiltinId, args: Vec<LuaValue>) -> Result<Vec<LuaValue>, VmError> {
        call_builtin(id, &args, &mut gas(), &mut mem(), &mut logs())
    }

    // ── type ──────────────────────────────────────────────────────────────────

    #[test]
    fn type_nil() {
        assert_eq!(
            dispatch(BuiltinId::Type, vec![LuaValue::Nil]).unwrap(),
            vec![s("nil")]
        );
    }

    #[test]
    fn type_boolean() {
        assert_eq!(
            dispatch(BuiltinId::Type, vec![LuaValue::Boolean(true)]).unwrap(),
            vec![s("boolean")]
        );
    }

    #[test]
    fn type_integer() {
        assert_eq!(
            dispatch(BuiltinId::Type, vec![int(0)]).unwrap(),
            vec![s("integer")]
        );
    }

    #[test]
    fn type_string() {
        assert_eq!(
            dispatch(BuiltinId::Type, vec![s("hi")]).unwrap(),
            vec![s("string")]
        );
    }

    #[test]
    fn type_table() {
        let t = tval(make_table());
        assert_eq!(
            dispatch(BuiltinId::Type, vec![t]).unwrap(),
            vec![s("table")]
        );
    }

    #[test]
    fn type_function() {
        assert_eq!(
            dispatch(BuiltinId::Type, vec![LuaValue::Builtin(BuiltinId::Type)]).unwrap(),
            vec![s("function")]
        );
    }

    // ── tostring ──────────────────────────────────────────────────────────────

    #[test]
    fn tostring_nil() {
        assert_eq!(
            dispatch(BuiltinId::Tostring, vec![LuaValue::Nil]).unwrap(),
            vec![s("nil")]
        );
    }

    #[test]
    fn tostring_true() {
        assert_eq!(
            dispatch(BuiltinId::Tostring, vec![LuaValue::Boolean(true)]).unwrap(),
            vec![s("true")]
        );
    }

    #[test]
    fn tostring_false() {
        assert_eq!(
            dispatch(BuiltinId::Tostring, vec![LuaValue::Boolean(false)]).unwrap(),
            vec![s("false")]
        );
    }

    #[test]
    fn tostring_integer() {
        assert_eq!(
            dispatch(BuiltinId::Tostring, vec![int(-42)]).unwrap(),
            vec![s("-42")]
        );
    }

    #[test]
    fn tostring_string_identity() {
        assert_eq!(
            dispatch(BuiltinId::Tostring, vec![s("hello")]).unwrap(),
            vec![s("hello")]
        );
    }

    // ── tonumber ──────────────────────────────────────────────────────────────

    #[test]
    fn tonumber_integer_passthrough() {
        assert_eq!(
            dispatch(BuiltinId::Tonumber, vec![int(5)]).unwrap(),
            vec![int(5)]
        );
    }

    #[test]
    fn tonumber_valid_string() {
        assert_eq!(
            dispatch(BuiltinId::Tonumber, vec![s("42")]).unwrap(),
            vec![int(42)]
        );
    }

    #[test]
    fn tonumber_string_with_whitespace() {
        assert_eq!(
            dispatch(BuiltinId::Tonumber, vec![s("  -7  ")]).unwrap(),
            vec![int(-7)]
        );
    }

    #[test]
    fn tonumber_invalid_string() {
        assert_eq!(
            dispatch(BuiltinId::Tonumber, vec![s("3.14")]).unwrap(),
            vec![LuaValue::Nil]
        );
    }

    #[test]
    fn tonumber_nil_returns_nil() {
        assert_eq!(
            dispatch(BuiltinId::Tonumber, vec![LuaValue::Nil]).unwrap(),
            vec![LuaValue::Nil]
        );
    }

    // ── select ────────────────────────────────────────────────────────────────

    #[test]
    fn select_basic() {
        let result = dispatch(BuiltinId::Select, vec![int(2), int(10), int(20), int(30)]).unwrap();
        assert_eq!(result, vec![int(20)]);
    }

    #[test]
    fn select_hash_returns_count() {
        let result = dispatch(BuiltinId::Select, vec![s("#"), int(10), int(20)]).unwrap();
        assert_eq!(result, vec![int(2)]);
    }

    #[test]
    fn select_negative_index() {
        let result = dispatch(BuiltinId::Select, vec![int(-1), int(10), int(20), int(30)]).unwrap();
        assert_eq!(result, vec![int(30)]);
    }

    // ── unpack ────────────────────────────────────────────────────────────────

    #[test]
    fn unpack_basic() {
        let t = make_table();
        t.borrow_mut().rawset(LuaKey::Integer(1), int(10)).unwrap();
        t.borrow_mut().rawset(LuaKey::Integer(2), int(20)).unwrap();
        t.borrow_mut().rawset(LuaKey::Integer(3), int(30)).unwrap();
        let result = dispatch(BuiltinId::Unpack, vec![tval(t)]).unwrap();
        assert_eq!(result, vec![int(10), int(20), int(30)]);
    }

    #[test]
    fn unpack_with_range() {
        let t = make_table();
        for i in 1..=5 {
            t.borrow_mut()
                .rawset(LuaKey::Integer(i), int(i * 10))
                .unwrap();
        }
        let result = dispatch(BuiltinId::Unpack, vec![tval(t), int(2), int(4)]).unwrap();
        assert_eq!(result, vec![int(20), int(30), int(40)]);
    }

    // ── string.len ────────────────────────────────────────────────────────────

    #[test]
    fn string_len_basic() {
        assert_eq!(
            dispatch(BuiltinId::StringLen, vec![s("hello")]).unwrap(),
            vec![int(5)]
        );
    }

    #[test]
    fn string_len_empty() {
        assert_eq!(
            dispatch(BuiltinId::StringLen, vec![s("")]).unwrap(),
            vec![int(0)]
        );
    }

    // ── string.sub ────────────────────────────────────────────────────────────

    #[test]
    fn string_sub_basic() {
        assert_eq!(
            dispatch(BuiltinId::StringSub, vec![s("hello"), int(2), int(4)]).unwrap(),
            vec![s("ell")]
        );
    }

    #[test]
    fn string_sub_negative_end() {
        assert_eq!(
            dispatch(BuiltinId::StringSub, vec![s("hello"), int(1), int(-2)]).unwrap(),
            vec![s("hell")]
        );
    }

    #[test]
    fn string_sub_negative_start() {
        assert_eq!(
            dispatch(BuiltinId::StringSub, vec![s("hello"), int(-3)]).unwrap(),
            vec![s("llo")]
        );
    }

    #[test]
    fn string_sub_out_of_range() {
        assert_eq!(
            dispatch(BuiltinId::StringSub, vec![s("hello"), int(10)]).unwrap(),
            vec![s("")]
        );
    }

    // ── string.find ───────────────────────────────────────────────────────────

    #[test]
    fn string_find_found() {
        let r = dispatch(BuiltinId::StringFind, vec![s("hello world"), s("world")]).unwrap();
        assert_eq!(r, vec![int(7), int(11)]);
    }

    #[test]
    fn string_find_not_found() {
        let r = dispatch(BuiltinId::StringFind, vec![s("hello"), s("xyz")]).unwrap();
        assert_eq!(r, vec![LuaValue::Nil, LuaValue::Nil]);
    }

    #[test]
    fn string_find_metachar_error() {
        let err = dispatch(BuiltinId::StringFind, vec![s("hello"), s("h.l")]).unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
    }

    #[test]
    fn string_find_with_init() {
        let r = dispatch(BuiltinId::StringFind, vec![s("abcabc"), s("b"), int(3)]).unwrap();
        assert_eq!(r, vec![int(5), int(5)]);
    }

    // ── string.find_literal ───────────────────────────────────────────────────

    #[test]
    fn string_find_literal_matches_dot() {
        let r = dispatch(BuiltinId::StringFindLiteral, vec![s("3245.67"), s(".")]).unwrap();
        assert_eq!(r, vec![int(5), int(5)]);
    }

    #[test]
    fn string_find_literal_matches_multi_metachar_substring() {
        let r = dispatch(
            BuiltinId::StringFindLiteral,
            vec![s("x a.b*c y"), s("a.b*c")],
        )
        .unwrap();
        assert_eq!(r, vec![int(3), int(7)]);
    }

    #[test]
    fn string_find_literal_not_found_returns_nil_pair() {
        let r = dispatch(BuiltinId::StringFindLiteral, vec![s("hello"), s("xyz")]).unwrap();
        assert_eq!(r, vec![LuaValue::Nil, LuaValue::Nil]);
    }

    #[test]
    fn string_find_literal_with_init_skips_prior_match() {
        let r = dispatch(
            BuiltinId::StringFindLiteral,
            vec![s("a.b.c"), s("."), int(3)],
        )
        .unwrap();
        assert_eq!(r, vec![int(4), int(4)]);
    }

    #[test]
    fn string_find_literal_init_past_end_returns_nil_pair() {
        let r = dispatch(
            BuiltinId::StringFindLiteral,
            vec![s("abc"), s("a"), int(99)],
        )
        .unwrap();
        assert_eq!(r, vec![LuaValue::Nil, LuaValue::Nil]);
    }

    #[test]
    fn string_find_literal_empty_needle_returns_init_position() {
        let r = dispatch(BuiltinId::StringFindLiteral, vec![s("hello"), s("")]).unwrap();
        assert_eq!(r, vec![int(1), int(0)]);
    }

    // ── string.upper / lower ──────────────────────────────────────────────────

    #[test]
    fn string_upper_basic() {
        assert_eq!(
            dispatch(BuiltinId::StringUpper, vec![s("hello")]).unwrap(),
            vec![s("HELLO")]
        );
    }

    #[test]
    fn string_lower_basic() {
        assert_eq!(
            dispatch(BuiltinId::StringLower, vec![s("HELLO")]).unwrap(),
            vec![s("hello")]
        );
    }

    // ── string.rep ────────────────────────────────────────────────────────────

    #[test]
    fn string_rep_basic() {
        assert_eq!(
            dispatch(BuiltinId::StringRep, vec![s("ab"), int(3)]).unwrap(),
            vec![s("ababab")]
        );
    }

    #[test]
    fn string_rep_zero() {
        assert_eq!(
            dispatch(BuiltinId::StringRep, vec![s("ab"), int(0)]).unwrap(),
            vec![s("")]
        );
    }

    #[test]
    fn string_rep_negative() {
        assert_eq!(
            dispatch(BuiltinId::StringRep, vec![s("ab"), int(-1)]).unwrap(),
            vec![s("")]
        );
    }

    // ── string.byte / char ────────────────────────────────────────────────────

    #[test]
    fn string_byte_single() {
        assert_eq!(
            dispatch(BuiltinId::StringByte, vec![s("A")]).unwrap(),
            vec![int(65)]
        );
    }

    #[test]
    fn string_byte_range() {
        assert_eq!(
            dispatch(BuiltinId::StringByte, vec![s("ABC"), int(1), int(3)]).unwrap(),
            vec![int(65), int(66), int(67)]
        );
    }

    #[test]
    fn string_char_basic() {
        assert_eq!(
            dispatch(BuiltinId::StringChar, vec![int(65), int(66), int(67)]).unwrap(),
            vec![s("ABC")]
        );
    }

    #[test]
    fn string_byte_char_roundtrip() {
        let bytes = dispatch(BuiltinId::StringByte, vec![s("hello"), int(1), int(5)]).unwrap();
        let back = dispatch(BuiltinId::StringChar, bytes).unwrap();
        assert_eq!(back, vec![s("hello")]);
    }

    // ── string.format ─────────────────────────────────────────────────────────

    #[test]
    fn string_format_d() {
        assert_eq!(
            dispatch(BuiltinId::StringFormat, vec![s("%d"), int(42)]).unwrap(),
            vec![s("42")]
        );
    }

    #[test]
    fn string_format_s() {
        assert_eq!(
            dispatch(BuiltinId::StringFormat, vec![s("%s"), s("world")]).unwrap(),
            vec![s("world")]
        );
    }

    #[test]
    fn string_format_x() {
        assert_eq!(
            dispatch(BuiltinId::StringFormat, vec![s("%x"), int(255)]).unwrap(),
            vec![s("ff")]
        );
    }

    #[test]
    fn string_format_percent() {
        assert_eq!(
            dispatch(BuiltinId::StringFormat, vec![s("100%%")]).unwrap(),
            vec![s("100%")]
        );
    }

    #[test]
    fn string_format_multiple() {
        assert_eq!(
            dispatch(
                BuiltinId::StringFormat,
                vec![s("%d + %d = %d"), int(1), int(2), int(3)]
            )
            .unwrap(),
            vec![s("1 + 2 = 3")]
        );
    }

    #[test]
    fn string_format_unsupported_spec() {
        let err = dispatch(BuiltinId::StringFormat, vec![s("%q"), s("x")]).unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
    }

    // ── math.abs ──────────────────────────────────────────────────────────────

    #[test]
    fn math_abs_positive() {
        assert_eq!(
            dispatch(BuiltinId::MathAbs, vec![int(5)]).unwrap(),
            vec![int(5)]
        );
    }

    #[test]
    fn math_abs_negative() {
        assert_eq!(
            dispatch(BuiltinId::MathAbs, vec![int(-5)]).unwrap(),
            vec![int(5)]
        );
    }

    #[test]
    fn math_abs_zero() {
        assert_eq!(
            dispatch(BuiltinId::MathAbs, vec![int(0)]).unwrap(),
            vec![int(0)]
        );
    }

    #[test]
    fn math_abs_min_wraps() {
        assert_eq!(
            dispatch(BuiltinId::MathAbs, vec![int(i64::MIN)]).unwrap(),
            vec![int(i64::MIN)]
        );
    }

    // ── math.min / max ────────────────────────────────────────────────────────

    #[test]
    fn math_min_basic() {
        assert_eq!(
            dispatch(BuiltinId::MathMin, vec![int(3), int(1), int(4)]).unwrap(),
            vec![int(1)]
        );
    }

    #[test]
    fn math_max_basic() {
        assert_eq!(
            dispatch(BuiltinId::MathMax, vec![int(3), int(1), int(4)]).unwrap(),
            vec![int(4)]
        );
    }

    #[test]
    fn math_min_single() {
        assert_eq!(
            dispatch(BuiltinId::MathMin, vec![int(7)]).unwrap(),
            vec![int(7)]
        );
    }

    // ── math.scale_div ────────────────────────────────────────────────────────

    #[test]
    fn math_scale_div_basic() {
        // (10 * 100) // 3 = 333
        assert_eq!(
            dispatch(BuiltinId::MathScaleDiv, vec![int(10), int(3), int(100)]).unwrap(),
            vec![int(333)]
        );
    }

    #[test]
    fn math_scale_div_zero_divisor() {
        let err = dispatch(BuiltinId::MathScaleDiv, vec![int(1), int(0), int(100)]).unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
    }

    // ── table.insert / remove ─────────────────────────────────────────────────

    #[test]
    fn table_insert_append() {
        let t = make_table();
        t.borrow_mut().rawset(LuaKey::Integer(1), int(10)).unwrap();
        t.borrow_mut().rawset(LuaKey::Integer(2), int(20)).unwrap();
        dispatch(BuiltinId::TableInsert, vec![tval(Rc::clone(&t)), int(30)]).unwrap();
        assert_eq!(t.borrow().get(&LuaKey::Integer(3)), Some(&int(30)));
        assert_eq!(t.borrow().length(), 3);
    }

    #[test]
    fn table_insert_at_pos() {
        let t = make_table();
        t.borrow_mut().rawset(LuaKey::Integer(1), int(1)).unwrap();
        t.borrow_mut().rawset(LuaKey::Integer(2), int(3)).unwrap();
        dispatch(
            BuiltinId::TableInsert,
            vec![tval(Rc::clone(&t)), int(2), int(2)],
        )
        .unwrap();
        assert_eq!(t.borrow().get(&LuaKey::Integer(1)), Some(&int(1)));
        assert_eq!(t.borrow().get(&LuaKey::Integer(2)), Some(&int(2)));
        assert_eq!(t.borrow().get(&LuaKey::Integer(3)), Some(&int(3)));
    }

    #[test]
    fn table_remove_last() {
        let t = make_table();
        for i in 1..=3 {
            t.borrow_mut()
                .rawset(LuaKey::Integer(i), int(i * 10))
                .unwrap();
        }
        let result = dispatch(BuiltinId::TableRemove, vec![tval(Rc::clone(&t))]).unwrap();
        assert_eq!(result, vec![int(30)]);
        assert_eq!(t.borrow().length(), 2);
    }

    #[test]
    fn table_remove_at_pos() {
        let t = make_table();
        for i in 1..=3 {
            t.borrow_mut()
                .rawset(LuaKey::Integer(i), int(i * 10))
                .unwrap();
        }
        let result = dispatch(BuiltinId::TableRemove, vec![tval(Rc::clone(&t)), int(2)]).unwrap();
        assert_eq!(result, vec![int(20)]);
        assert_eq!(t.borrow().length(), 2);
        assert_eq!(t.borrow().get(&LuaKey::Integer(1)), Some(&int(10)));
        assert_eq!(t.borrow().get(&LuaKey::Integer(2)), Some(&int(30)));
    }

    // ── table.concat ──────────────────────────────────────────────────────────

    #[test]
    fn table_concat_basic() {
        let t = make_table();
        for (i, w) in ["a", "b", "c"].iter().enumerate() {
            t.borrow_mut()
                .rawset(LuaKey::Integer((i + 1) as i64), s(w))
                .unwrap();
        }
        let result = dispatch(BuiltinId::TableConcat, vec![tval(t), s(",")]).unwrap();
        assert_eq!(result, vec![s("a,b,c")]);
    }

    #[test]
    fn table_concat_no_sep() {
        let t = make_table();
        for (i, w) in ["x", "y"].iter().enumerate() {
            t.borrow_mut()
                .rawset(LuaKey::Integer((i + 1) as i64), s(w))
                .unwrap();
        }
        let result = dispatch(BuiltinId::TableConcat, vec![tval(t)]).unwrap();
        assert_eq!(result, vec![s("xy")]);
    }

    #[test]
    fn table_concat_partial_range() {
        let t = make_table();
        for i in 1..=5 {
            t.borrow_mut()
                .rawset(LuaKey::Integer(i), s(&i.to_string()))
                .unwrap();
        }
        let result = dispatch(
            BuiltinId::TableConcat,
            vec![tval(t), s("-"), int(2), int(4)],
        )
        .unwrap();
        assert_eq!(result, vec![s("2-3-4")]);
    }

    // ── table.sort ────────────────────────────────────────────────────────────

    #[test]
    fn table_sort_merge_sort_integers() {
        let t = make_table();
        let data = vec![3i64, 1, 4, 1, 5, 9, 2, 6];
        for (i, &v) in data.iter().enumerate() {
            t.borrow_mut()
                .rawset(LuaKey::Integer((i + 1) as i64), int(v))
                .unwrap();
        }
        let n = t.borrow().length() as usize;
        merge_sort_table(&t, &mut gas(), n, |a, b| {
            Ok(a.lua_cmp(b).map(|o| o.is_lt()).unwrap_or(false))
        })
        .unwrap();
        let expected = vec![1, 1, 2, 3, 4, 5, 6, 9];
        for (i, &v) in expected.iter().enumerate() {
            assert_eq!(
                t.borrow().get(&LuaKey::Integer((i + 1) as i64)),
                Some(&int(v))
            );
        }
    }

    #[test]
    fn table_sort_empty() {
        let t = make_table();
        merge_sort_table(&t, &mut gas(), 0, |_, _| Ok(false)).unwrap();
        assert_eq!(t.borrow().length(), 0);
    }

    // ── table.move ────────────────────────────────────────────────────────────

    #[test]
    fn table_move_basic() {
        let t = make_table();
        for i in 1..=4 {
            t.borrow_mut()
                .rawset(LuaKey::Integer(i), int(i * 10))
                .unwrap();
        }
        dispatch(
            BuiltinId::TableMove,
            vec![tval(Rc::clone(&t)), int(1), int(3), int(2)],
        )
        .unwrap();
        assert_eq!(t.borrow().get(&LuaKey::Integer(2)), Some(&int(10)));
        assert_eq!(t.borrow().get(&LuaKey::Integer(3)), Some(&int(20)));
        assert_eq!(t.borrow().get(&LuaKey::Integer(4)), Some(&int(30)));
    }

    // ── json.encode ───────────────────────────────────────────────────────────

    #[test]
    fn json_encode_null() {
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![LuaValue::Nil]).unwrap(),
            vec![s("null")]
        );
    }

    #[test]
    fn json_encode_bool() {
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![LuaValue::Boolean(true)]).unwrap(),
            vec![s("true")]
        );
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![LuaValue::Boolean(false)]).unwrap(),
            vec![s("false")]
        );
    }

    #[test]
    fn json_encode_integer() {
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![int(42)]).unwrap(),
            vec![s("42")]
        );
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![int(-1)]).unwrap(),
            vec![s("-1")]
        );
    }

    #[test]
    fn json_encode_string() {
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![s("hello")]).unwrap(),
            vec![s("\"hello\"")]
        );
    }

    #[test]
    fn json_encode_string_escapes() {
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![s("a\"b")]).unwrap(),
            vec![s(r#""a\"b""#)]
        );
    }

    #[test]
    fn json_encode_array() {
        let t = make_table();
        for i in 1..=3 {
            t.borrow_mut()
                .rawset(LuaKey::Integer(i), int(i * 10))
                .unwrap();
        }
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![tval(t)]).unwrap(),
            vec![s("[10,20,30]")]
        );
    }

    #[test]
    fn json_encode_object() {
        let t = make_table();
        t.borrow_mut()
            .rawset(LuaKey::String(LuaString::from_str("a")), int(1))
            .unwrap();
        let result = dispatch(BuiltinId::JsonEncode, vec![tval(t)]).unwrap();
        assert_eq!(result, vec![s(r#"{"a":1}"#)]);
    }

    #[test]
    fn json_encode_function_error() {
        let err = dispatch(
            BuiltinId::JsonEncode,
            vec![LuaValue::Builtin(BuiltinId::Type)],
        )
        .unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
    }

    // ── json.decode ───────────────────────────────────────────────────────────

    #[test]
    fn json_decode_null() {
        assert_eq!(
            dispatch(BuiltinId::JsonDecode, vec![s("null")]).unwrap(),
            vec![LuaValue::Nil]
        );
    }

    #[test]
    fn json_decode_bool() {
        assert_eq!(
            dispatch(BuiltinId::JsonDecode, vec![s("true")]).unwrap(),
            vec![LuaValue::Boolean(true)]
        );
        assert_eq!(
            dispatch(BuiltinId::JsonDecode, vec![s("false")]).unwrap(),
            vec![LuaValue::Boolean(false)]
        );
    }

    #[test]
    fn json_decode_integer() {
        assert_eq!(
            dispatch(BuiltinId::JsonDecode, vec![s("42")]).unwrap(),
            vec![int(42)]
        );
        assert_eq!(
            dispatch(BuiltinId::JsonDecode, vec![s("-7")]).unwrap(),
            vec![int(-7)]
        );
    }

    #[test]
    fn json_decode_string() {
        let result = dispatch(BuiltinId::JsonDecode, vec![s(r#""hello""#)]).unwrap();
        assert_eq!(result, vec![s("hello")]);
    }

    #[test]
    fn json_decode_array() {
        let result = dispatch(BuiltinId::JsonDecode, vec![s("[1,2,3]")]).unwrap();
        assert_eq!(result.len(), 1);
        if let LuaValue::Table(t) = &result[0] {
            assert_eq!(t.borrow().get(&LuaKey::Integer(1)), Some(&int(1)));
            assert_eq!(t.borrow().get(&LuaKey::Integer(3)), Some(&int(3)));
        } else {
            panic!("expected table");
        }
    }

    #[test]
    fn json_decode_object() {
        let result = dispatch(BuiltinId::JsonDecode, vec![s(r#"{"x":99}"#)]).unwrap();
        assert_eq!(result.len(), 1);
        if let LuaValue::Table(t) = &result[0] {
            let key = LuaKey::String(LuaString::from_str("x"));
            assert_eq!(t.borrow().get(&key), Some(&int(99)));
        } else {
            panic!("expected table");
        }
    }

    #[test]
    fn json_decode_fractional_error() {
        let err = dispatch(BuiltinId::JsonDecode, vec![s("3.14")]).unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
    }

    #[test]
    fn json_encode_decode_roundtrip() {
        let t = make_table();
        t.borrow_mut().rawset(LuaKey::Integer(1), int(1)).unwrap();
        t.borrow_mut()
            .rawset(LuaKey::Integer(2), s("hello"))
            .unwrap();
        t.borrow_mut()
            .rawset(LuaKey::Integer(3), LuaValue::Nil)
            .unwrap();

        let encoded = dispatch(BuiltinId::JsonEncode, vec![tval(Rc::clone(&t))]).unwrap();
        let decoded = dispatch(BuiltinId::JsonDecode, encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(matches!(decoded[0], LuaValue::Table(_)));
    }

    // ── json.decode trailing input ────────────────────────────────────────────

    #[test]
    fn json_decode_trailing_non_whitespace_errors() {
        let err = dispatch(BuiltinId::JsonDecode, vec![s("42abc")]).unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
    }

    #[test]
    fn json_decode_trailing_whitespace_ok() {
        let result = dispatch(BuiltinId::JsonDecode, vec![s("42   ")]).unwrap();
        assert_eq!(result, vec![int(42)]);
    }

    #[test]
    fn json_decode_trailing_newline_ok() {
        let result = dispatch(BuiltinId::JsonDecode, vec![s("null\n")]).unwrap();
        assert_eq!(result, vec![LuaValue::Nil]);
    }

    // ── json.decode depth limits ──────────────────────────────────────────────

    #[test]
    fn json_decode_depth_32_ok() {
        // 32 nested arrays should succeed.
        let json = format!("{}1{}", "[".repeat(32), "]".repeat(32));
        let result = dispatch(BuiltinId::JsonDecode, vec![s(&json)]).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn json_decode_depth_33_error() {
        // 33 nested arrays should hit the depth limit.
        let json = format!("{}1{}", "[".repeat(33), "]".repeat(33));
        let err = dispatch(BuiltinId::JsonDecode, vec![s(&json)]).unwrap_err();
        assert!(
            matches!(err, VmError::RuntimeError(_)),
            "expected RuntimeError for depth-33, got {err:?}"
        );
    }

    // ── json.decode memory accounting ────────────────────────────────────────

    #[test]
    fn json_decode_memory_charged_for_table_growth() {
        // N=17 guarantees at least one hash-capacity growth.
        let items: Vec<String> = (1..=17).map(|i| i.to_string()).collect();
        let json = format!("[{}]", items.join(","));
        let input = s(&json);

        // With a very tight memory budget, decoding should fail.
        let mut tiny_mem = MemoryMeter::new(50);
        let mut g = gas();
        let result = call_builtin(
            BuiltinId::JsonDecode,
            &[input.clone()],
            &mut g,
            &mut tiny_mem,
            &mut logs(),
        );
        assert!(
            matches!(result, Err(VmError::MemoryExhausted)),
            "expected MemoryExhausted with tiny budget"
        );

        // With the default budget it must succeed.
        let result = dispatch(BuiltinId::JsonDecode, vec![input]);
        assert!(
            result.is_ok(),
            "expected success with default memory budget"
        );
    }

    // ── json.encode edge cases ────────────────────────────────────────────────

    #[test]
    fn json_encode_negative_integer() {
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![int(-42)]).unwrap(),
            vec![s("-42")]
        );
    }

    #[test]
    fn json_encode_i64_min_max() {
        let min_str = i64::MIN.to_string();
        let max_str = i64::MAX.to_string();
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![int(i64::MIN)]).unwrap(),
            vec![s(&min_str)]
        );
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![int(i64::MAX)]).unwrap(),
            vec![s(&max_str)]
        );
    }

    #[test]
    fn json_encode_empty_table_is_object() {
        let t = make_table();
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![tval(t)]).unwrap(),
            vec![s("{}")]
        );
    }

    #[test]
    fn json_encode_non_consecutive_keys() {
        // {1:10, 3:30} — gap means it encodes as object, not array.
        let t = make_table();
        t.borrow_mut().rawset(LuaKey::Integer(1), int(10)).unwrap();
        t.borrow_mut().rawset(LuaKey::Integer(3), int(30)).unwrap();
        let result = dispatch(BuiltinId::JsonEncode, vec![tval(t)]).unwrap();
        assert_eq!(result.len(), 1);
        // Must be a JSON object (starts with '{') since keys are not consecutive.
        if let LuaValue::String(encoded) = &result[0] {
            let s = core::str::from_utf8(encoded.as_bytes()).unwrap();
            assert!(s.starts_with('{'), "expected object encoding, got: {s}");
        } else {
            panic!("expected string result");
        }
    }

    #[test]
    fn json_encode_nested_array() {
        let inner1 = make_table();
        inner1
            .borrow_mut()
            .rawset(LuaKey::Integer(1), int(1))
            .unwrap();
        inner1
            .borrow_mut()
            .rawset(LuaKey::Integer(2), int(2))
            .unwrap();
        let inner2 = make_table();
        inner2
            .borrow_mut()
            .rawset(LuaKey::Integer(1), int(3))
            .unwrap();
        inner2
            .borrow_mut()
            .rawset(LuaKey::Integer(2), int(4))
            .unwrap();
        let outer = make_table();
        outer
            .borrow_mut()
            .rawset(LuaKey::Integer(1), tval(inner1))
            .unwrap();
        outer
            .borrow_mut()
            .rawset(LuaKey::Integer(2), tval(inner2))
            .unwrap();
        assert_eq!(
            dispatch(BuiltinId::JsonEncode, vec![tval(outer)]).unwrap(),
            vec![s("[[1,2],[3,4]]")]
        );
    }

    #[test]
    fn json_encode_unicode_escape() {
        // Byte 0x01 (control character) must be encoded as \u0001.
        let result = dispatch(
            BuiltinId::JsonEncode,
            vec![LuaValue::String(LuaString::from_bytes(&[0x01]))],
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        if let LuaValue::String(encoded) = &result[0] {
            let s = core::str::from_utf8(encoded.as_bytes()).unwrap();
            assert!(s.contains("\\u0001"), "expected \\u0001 escape, got: {s}");
        } else {
            panic!("expected string");
        }
    }

    #[test]
    fn json_encode_closure_error() {
        use crate::types::value::LuaClosure;
        let closure = LuaValue::Function(LuaClosure {
            proto_idx: 0,
            upvalues: vec![],
        });
        let err = dispatch(BuiltinId::JsonEncode, vec![closure]).unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
    }

    // ── json.decode edge cases ────────────────────────────────────────────────

    #[test]
    fn json_decode_unicode_escape() {
        // \u0041 is 'A'.
        let result = dispatch(BuiltinId::JsonDecode, vec![s(r#""\u0041""#)]).unwrap();
        assert_eq!(result, vec![s("A")]);
    }

    #[test]
    fn json_decode_empty_array() {
        let result = dispatch(BuiltinId::JsonDecode, vec![s("[]")]).unwrap();
        assert_eq!(result.len(), 1);
        if let LuaValue::Table(t) = &result[0] {
            assert_eq!(t.borrow().length(), 0);
        } else {
            panic!("expected table");
        }
    }

    #[test]
    fn json_decode_empty_object() {
        let result = dispatch(BuiltinId::JsonDecode, vec![s("{}")]).unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], LuaValue::Table(_)));
    }

    #[test]
    fn json_decode_nested_object() {
        let result = dispatch(BuiltinId::JsonDecode, vec![s(r#"{"a":{"b":1}}"#)]).unwrap();
        if let LuaValue::Table(outer) = &result[0] {
            let inner_key = LuaKey::String(LuaString::from_str("a"));
            let inner_val = outer.borrow().get(&inner_key).cloned().unwrap();
            if let LuaValue::Table(inner) = inner_val {
                let b_key = LuaKey::String(LuaString::from_str("b"));
                assert_eq!(inner.borrow().get(&b_key), Some(&int(1)));
            } else {
                panic!("expected inner table");
            }
        } else {
            panic!("expected outer table");
        }
    }

    #[test]
    fn json_decode_integer_zero() {
        assert_eq!(
            dispatch(BuiltinId::JsonDecode, vec![s("0")]).unwrap(),
            vec![int(0)]
        );
    }

    #[test]
    fn json_decode_integer_negative() {
        assert_eq!(
            dispatch(BuiltinId::JsonDecode, vec![s("-99")]).unwrap(),
            vec![int(-99)]
        );
    }

    #[test]
    fn json_decode_i64_max() {
        let max_str = i64::MAX.to_string();
        assert_eq!(
            dispatch(BuiltinId::JsonDecode, vec![s(&max_str)]).unwrap(),
            vec![int(i64::MAX)]
        );
    }

    #[test]
    fn json_decode_i64_overflow_errors() {
        // i64::MAX + 1 overflows.
        let overflow = format!("{}", i64::MAX as u64 + 1);
        let err = dispatch(BuiltinId::JsonDecode, vec![s(&overflow)]).unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
    }

    #[test]
    fn json_decode_exponent_errors() {
        let err = dispatch(BuiltinId::JsonDecode, vec![s("1e5")]).unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
    }

    #[test]
    fn json_decode_empty_string_errors() {
        let err = dispatch(BuiltinId::JsonDecode, vec![s("")]).unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
    }

    #[test]
    fn json_decode_invalid_escape_errors() {
        let err = dispatch(BuiltinId::JsonDecode, vec![s("\"\\q\"")]).unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
    }

    // ── ceil_log2 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_ceil_log2() {
        assert_eq!(ceil_log2(0), 0);
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(4), 2);
        assert_eq!(ceil_log2(5), 3);
        assert_eq!(ceil_log2(8), 3);
    }
}
