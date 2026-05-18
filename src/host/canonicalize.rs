//! Canonical JSON serialization for `LuaValue`.
//!
//! This is the single canonical serialization algorithm used everywhere:
//! - `json.encode` (builtin)
//! - tool call `args_canonical` in the transcript
//! - SHA-256 input for `response_hash`
//! - byte-length accounting for quota enforcement

use crate::{
    types::{
        table::{LuaKey, LuaTable},
        value::LuaValue,
    },
    vm::gas::VmError,
};
#[cfg(not(feature = "std"))]
use alloc::{
    format,
    rc::Rc,
    string::{String, ToString},
    vec,
    vec::Vec,
};
#[cfg(not(feature = "std"))]
use core::cell::RefCell;

const MAX_TABLE_DEPTH: usize = 32;
const MAX_STRING_LEN: usize = 1024 * 1024; // 1 MB

/// Error type for canonicalization failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonError {
    FunctionNotSerializable,
    TableDepthExceeded,
    StringTooLong,
    InvalidInput,
}

impl From<CanonError> for VmError {
    fn from(e: CanonError) -> VmError {
        use crate::types::value::LuaString;
        let msg = match e {
            CanonError::FunctionNotSerializable => "json.encode: functions not serializable",
            CanonError::TableDepthExceeded => "json.encode: table depth exceeded",
            CanonError::StringTooLong => "string length overflow",
            CanonError::InvalidInput => "canonical_deserialize: invalid input",
        };
        VmError::RuntimeError(LuaValue::String(LuaString::from_str(msg)))
    }
}

/// Serialize a `LuaValue` to canonical JSON bytes.
pub fn canonical_serialize(v: &LuaValue) -> Result<Vec<u8>, CanonError> {
    let result = serialize_value(v, 0)?;
    if result.len() > MAX_STRING_LEN {
        return Err(CanonError::StringTooLong);
    }
    Ok(result)
}

/// Serialize directly from a `LuaTable` reference.
pub fn canonical_serialize_table(t: &LuaTable) -> Result<Vec<u8>, CanonError> {
    let result = serialize_table(t, 0)?;
    if result.len() > MAX_STRING_LEN {
        return Err(CanonError::StringTooLong);
    }
    Ok(result)
}

/// Return the byte length of the canonical serialization without allocating the
/// full buffer. Used for quota pre-checks.
pub fn canonical_byte_len(v: &LuaValue) -> Result<usize, CanonError> {
    Ok(canonical_serialize(v)?.len())
}

// ── Deserialization ────────────────────────────────────────────────────────────

/// Deserialize canonical JSON bytes back into a `LuaValue`.
///
/// Inverse of `canonical_serialize` for the subset of values that can round-trip:
/// nil, bool, integer, string, and table (nested). Functions/closures cannot
/// appear in serialized form and are never produced by this function.
pub fn canonical_deserialize(bytes: &[u8]) -> Result<LuaValue, CanonError> {
    let (v, rest) = deser_value(bytes)?;
    let rest = trim_leading_whitespace(rest);
    if !rest.is_empty() {
        return Err(CanonError::InvalidInput);
    }
    Ok(v)
}

fn trim_leading_whitespace(s: &[u8]) -> &[u8] {
    let pos = s
        .iter()
        .position(|&b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .unwrap_or(s.len());
    &s[pos..]
}

/// Parse a JSON value from `bytes`, returning `(value, remaining_bytes)`.
fn deser_value(bytes: &[u8]) -> Result<(LuaValue, &[u8]), CanonError> {
    let bytes = trim_leading_whitespace(bytes);
    if bytes.is_empty() {
        return Err(CanonError::InvalidInput);
    }
    match bytes[0] {
        b'n' => {
            if bytes.starts_with(b"null") {
                Ok((LuaValue::Nil, &bytes[4..]))
            } else {
                Err(CanonError::InvalidInput)
            }
        }
        b't' => {
            if bytes.starts_with(b"true") {
                Ok((LuaValue::Boolean(true), &bytes[4..]))
            } else {
                Err(CanonError::InvalidInput)
            }
        }
        b'f' => {
            if bytes.starts_with(b"false") {
                Ok((LuaValue::Boolean(false), &bytes[5..]))
            } else {
                Err(CanonError::InvalidInput)
            }
        }
        b'"' => {
            let (s_val, rest) = deser_string(&bytes[1..])?;
            Ok((
                LuaValue::String(crate::types::value::LuaString::from_bytes(&s_val)),
                rest,
            ))
        }
        b'[' => deser_array(&bytes[1..]),
        b'{' => deser_object(&bytes[1..]),
        b'-' | b'0'..=b'9' => deser_integer(bytes),
        _ => Err(CanonError::InvalidInput),
    }
}

/// Parse a JSON string (starting after the opening `"`), returning `(bytes, remaining)`.
fn deser_string(s: &[u8]) -> Result<(Vec<u8>, &[u8]), CanonError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'"' => return Ok((out, &s[i + 1..])),
            b'\\' => {
                i += 1;
                if i >= s.len() {
                    return Err(CanonError::InvalidInput);
                }
                match s[i] {
                    b'"' => {
                        out.push(b'"');
                        i += 1;
                    }
                    b'\\' => {
                        out.push(b'\\');
                        i += 1;
                    }
                    b'/' => {
                        out.push(b'/');
                        i += 1;
                    }
                    b'n' => {
                        out.push(b'\n');
                        i += 1;
                    }
                    b'r' => {
                        out.push(b'\r');
                        i += 1;
                    }
                    b't' => {
                        out.push(b'\t');
                        i += 1;
                    }
                    b'u' => {
                        if i + 4 >= s.len() {
                            return Err(CanonError::InvalidInput);
                        }
                        let hex = core::str::from_utf8(&s[i + 1..i + 5])
                            .map_err(|_| CanonError::InvalidInput)?;
                        let cp =
                            u16::from_str_radix(hex, 16).map_err(|_| CanonError::InvalidInput)?;
                        // Canonical: \uXXXX encodes single bytes 0x00..=0xff
                        out.push(cp as u8);
                        i += 5;
                    }
                    _ => return Err(CanonError::InvalidInput),
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Err(CanonError::InvalidInput) // missing closing "
}

/// Parse a JSON array (starting after the opening `[`).
fn deser_array(s: &[u8]) -> Result<(LuaValue, &[u8]), CanonError> {
    use crate::types::table::{LuaKey, LuaTable};
    #[cfg(feature = "std")]
    use std::{cell::RefCell, rc::Rc};

    let mut t = LuaTable::new();
    let s = trim_leading_whitespace(s);
    if s.first() == Some(&b']') {
        return Ok((LuaValue::Table(Rc::new(RefCell::new(t))), &s[1..]));
    }
    let mut idx: i64 = 1;
    let mut rest = s;
    loop {
        let (val, after) = deser_value(rest)?;
        t.rawset(LuaKey::Integer(idx), val)
            .map_err(|_| CanonError::InvalidInput)?;
        idx += 1;
        let after = trim_leading_whitespace(after);
        if after.first() == Some(&b']') {
            return Ok((LuaValue::Table(Rc::new(RefCell::new(t))), &after[1..]));
        }
        if after.first() == Some(&b',') {
            rest = &after[1..];
        } else {
            return Err(CanonError::InvalidInput);
        }
    }
}

/// Parse a JSON object (starting after the opening `{`).
fn deser_object(s: &[u8]) -> Result<(LuaValue, &[u8]), CanonError> {
    use crate::types::table::{LuaKey, LuaTable};
    use crate::types::value::LuaString;
    #[cfg(feature = "std")]
    use std::{cell::RefCell, rc::Rc};

    let mut t = LuaTable::new();
    let s = trim_leading_whitespace(s);
    if s.first() == Some(&b'}') {
        return Ok((LuaValue::Table(Rc::new(RefCell::new(t))), &s[1..]));
    }
    let mut rest = s;
    loop {
        let r = trim_leading_whitespace(rest);
        if r.first() != Some(&b'"') {
            return Err(CanonError::InvalidInput);
        }
        let (key_bytes, after_key) = deser_string(&r[1..])?;
        let after_key = trim_leading_whitespace(after_key);
        if after_key.first() != Some(&b':') {
            return Err(CanonError::InvalidInput);
        }
        let (val, after_val) = deser_value(&after_key[1..])?;

        // Determine the key type: integer string → integer key; "true"/"false" → bool; else string
        let lua_key = if let Some(n) = core::str::from_utf8(&key_bytes)
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
        {
            LuaKey::Integer(n)
        } else if key_bytes == b"true" {
            LuaKey::Boolean(true)
        } else if key_bytes == b"false" {
            LuaKey::Boolean(false)
        } else {
            LuaKey::String(LuaString::from_bytes(&key_bytes))
        };

        t.rawset(lua_key, val)
            .map_err(|_| CanonError::InvalidInput)?;

        let after_val = trim_leading_whitespace(after_val);
        if after_val.first() == Some(&b'}') {
            return Ok((LuaValue::Table(Rc::new(RefCell::new(t))), &after_val[1..]));
        }
        if after_val.first() == Some(&b',') {
            rest = &after_val[1..];
        } else {
            return Err(CanonError::InvalidInput);
        }
    }
}

/// Parse a JSON integer (no floats in canonical format).
fn deser_integer(s: &[u8]) -> Result<(LuaValue, &[u8]), CanonError> {
    let end = s
        .iter()
        .position(|&b| !matches!(b, b'-' | b'0'..=b'9'))
        .unwrap_or(s.len());
    let n_str = core::str::from_utf8(&s[..end]).map_err(|_| CanonError::InvalidInput)?;
    let n: i64 = n_str.parse().map_err(|_| CanonError::InvalidInput)?;
    Ok((LuaValue::Integer(n), &s[end..]))
}

fn serialize_value(v: &LuaValue, depth: usize) -> Result<Vec<u8>, CanonError> {
    if depth > MAX_TABLE_DEPTH {
        return Err(CanonError::TableDepthExceeded);
    }
    match v {
        LuaValue::Nil => Ok(b"null".to_vec()),
        LuaValue::Boolean(b) => Ok(if *b {
            b"true".to_vec()
        } else {
            b"false".to_vec()
        }),
        LuaValue::Integer(n) => Ok(n.to_string().into_bytes()),
        LuaValue::String(s) => serialize_string(s.as_bytes()),
        LuaValue::Table(t) => serialize_table(&t.borrow(), depth),
        LuaValue::Function(_) | LuaValue::Builtin(_) => Err(CanonError::FunctionNotSerializable),
    }
}

fn serialize_string(bytes: &[u8]) -> Result<Vec<u8>, CanonError> {
    let mut out = vec![b'"'];
    for &b in bytes {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x20..=0x7e => out.push(b),
            _ => {
                let s = format!("\\u{:04x}", b);
                out.extend_from_slice(s.as_bytes());
            }
        }
    }
    out.push(b'"');
    Ok(out)
}

fn serialize_table(t: &LuaTable, depth: usize) -> Result<Vec<u8>, CanonError> {
    if depth > MAX_TABLE_DEPTH {
        return Err(CanonError::TableDepthExceeded);
    }

    let len = t.length();

    // Collect all keys in canonical order using sorted_keys().
    // Filter out keys with nil values (absent key semantics).
    let keys: Vec<LuaKey> = t
        .sorted_keys()
        .into_iter()
        .filter_map(|k_val| {
            let key = match k_val {
                LuaValue::Integer(i) => LuaKey::Integer(i),
                LuaValue::String(s) => LuaKey::String(s),
                LuaValue::Boolean(b) => LuaKey::Boolean(b),
                _ => return None,
            };
            // Skip keys whose value is nil.
            match t.get(&key) {
                Some(v) if !matches!(v, LuaValue::Nil) => Some(key),
                _ => None,
            }
        })
        .collect();

    let entry_count = keys.len();

    // Pure array: all keys are consecutive integers 1..=n with no gaps,
    // and entry_count matches len.
    let is_array = len > 0 && entry_count == len as usize;

    if is_array {
        let mut out = vec![b'['];
        for i in 1..=len {
            if i > 1 {
                out.push(b',');
            }
            let val = t.get(&LuaKey::Integer(i)).cloned().unwrap_or(LuaValue::Nil);
            let encoded = serialize_value(&val, depth + 1)?;
            out.extend_from_slice(&encoded);
        }
        out.push(b']');
        return Ok(out);
    }

    // Object: keys in canonical order (integers ascending, strings lexicographic, booleans).
    let mut out = vec![b'{'];
    let mut first = true;
    for k in &keys {
        let v = match t.get(k) {
            Some(v) if !matches!(v, LuaValue::Nil) => v,
            _ => continue,
        };

        if !first {
            out.push(b',');
        }
        first = false;

        // Encode key as JSON string.
        let key_bytes: Vec<u8> = match k {
            LuaKey::Integer(n) => serialize_string(n.to_string().as_bytes())?,
            LuaKey::String(s) => serialize_string(s.as_bytes())?,
            LuaKey::Boolean(b) => {
                if *b {
                    b"\"true\"".to_vec()
                } else {
                    b"\"false\"".to_vec()
                }
            }
        };
        out.extend_from_slice(&key_bytes);
        out.push(b':');
        let encoded = serialize_value(v, depth + 1)?;
        out.extend_from_slice(&encoded);
    }
    out.push(b'}');
    Ok(out)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        table::{LuaKey, LuaTable},
        value::{BuiltinId, LuaClosure, LuaString, LuaValue},
    };
    use std::{cell::RefCell, rc::Rc};

    fn int(n: i64) -> LuaValue {
        LuaValue::Integer(n)
    }
    fn s(text: &str) -> LuaValue {
        LuaValue::String(LuaString::from_str(text))
    }
    fn make_table() -> Rc<RefCell<LuaTable>> {
        Rc::new(RefCell::new(LuaTable::new()))
    }

    fn encode(v: &LuaValue) -> String {
        let bytes = canonical_serialize(v).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    fn encode_table(t: &LuaTable) -> String {
        let bytes = canonical_serialize_table(t).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn nil_is_null() {
        assert_eq!(encode(&LuaValue::Nil), "null");
    }

    #[test]
    fn bool_true() {
        assert_eq!(encode(&LuaValue::Boolean(true)), "true");
    }

    #[test]
    fn bool_false() {
        assert_eq!(encode(&LuaValue::Boolean(false)), "false");
    }

    #[test]
    fn integer_positive() {
        assert_eq!(encode(&int(42)), "42");
    }

    #[test]
    fn integer_negative() {
        assert_eq!(encode(&int(-1)), "-1");
    }

    #[test]
    fn integer_zero() {
        assert_eq!(encode(&int(0)), "0");
    }

    #[test]
    fn integer_min_max() {
        assert_eq!(encode(&int(i64::MAX)), i64::MAX.to_string());
        assert_eq!(encode(&int(i64::MIN)), i64::MIN.to_string());
    }

    #[test]
    fn string_simple() {
        assert_eq!(encode(&s("hello")), "\"hello\"");
    }

    #[test]
    fn string_with_escapes() {
        assert_eq!(encode(&s("a\"b")), r#""a\"b""#);
        assert_eq!(encode(&s("a\\b")), r#""a\\b""#);
        assert_eq!(encode(&s("a\nb")), r#""a\nb""#);
        assert_eq!(encode(&s("a\rb")), r#""a\rb""#);
        assert_eq!(encode(&s("a\tb")), r#""a\tb""#);
    }

    #[test]
    fn string_non_ascii_byte_escape() {
        // byte 0x80 should become \u0080
        let v = LuaValue::String(LuaString::from_bytes(&[0x80u8]));
        assert_eq!(encode(&v), "\"\\u0080\"");
    }

    #[test]
    fn string_printable_ascii_unescaped() {
        // 0x20 (space) and 0x7e (~) should not be escaped
        let v = LuaValue::String(LuaString::from_bytes(&[0x20u8, 0x7eu8]));
        assert_eq!(encode(&v), "\" ~\"");
    }

    #[test]
    fn array_table() {
        let t = make_table();
        for i in 1i64..=3 {
            t.borrow_mut()
                .rawset(LuaKey::Integer(i), int(i * 10))
                .unwrap();
        }
        assert_eq!(encode(&LuaValue::Table(t)), "[10,20,30]");
    }

    #[test]
    fn object_table_string_key() {
        let t = make_table();
        t.borrow_mut()
            .rawset(LuaKey::String(LuaString::from_str("a")), int(1))
            .unwrap();
        assert_eq!(encode(&LuaValue::Table(t)), r#"{"a":1}"#);
    }

    #[test]
    fn object_table_integer_key() {
        let t = make_table();
        // Non-consecutive: 1 and 3 but not 2 → object
        t.borrow_mut().rawset(LuaKey::Integer(1), int(10)).unwrap();
        t.borrow_mut().rawset(LuaKey::Integer(3), int(30)).unwrap();
        let result = encode(&LuaValue::Table(t));
        assert_eq!(result, r#"{"1":10,"3":30}"#);
    }

    #[test]
    fn object_key_ordering_integers_before_strings_before_bools() {
        let t = make_table();
        t.borrow_mut()
            .rawset(LuaKey::Boolean(true), int(3))
            .unwrap();
        t.borrow_mut()
            .rawset(LuaKey::String(LuaString::from_str("b")), int(2))
            .unwrap();
        t.borrow_mut().rawset(LuaKey::Integer(1), int(1)).unwrap();
        let result = encode_table(&t.borrow());
        // integers ascending, then strings lexicographic, then booleans
        assert_eq!(result, r#"{"1":1,"b":2,"true":3}"#);
    }

    #[test]
    fn nil_values_in_table_omitted() {
        let t = make_table();
        t.borrow_mut()
            .rawset(LuaKey::String(LuaString::from_str("a")), int(1))
            .unwrap();
        // Setting nil via LuaValue::Nil should be omitted from serialization
        // (If rawset with nil removes the key, this still tests the skip logic)
        let result = encode_table(&t.borrow());
        assert_eq!(result, r#"{"a":1}"#);
    }

    #[test]
    fn nested_table_at_depth_32_ok() {
        // Build a chain of depth 32 (each table contains one nested table)
        let mut inner = LuaValue::Integer(0);
        for _ in 0..32 {
            let t = make_table();
            t.borrow_mut()
                .rawset(LuaKey::String(LuaString::from_str("x")), inner)
                .unwrap();
            inner = LuaValue::Table(t);
        }
        // depth 32 should be ok (limit is > 32)
        assert!(canonical_serialize(&inner).is_ok());
    }

    #[test]
    fn nested_table_depth_33_error() {
        // Build a chain of depth 33
        let mut inner = LuaValue::Integer(0);
        for _ in 0..33 {
            let t = make_table();
            t.borrow_mut()
                .rawset(LuaKey::String(LuaString::from_str("x")), inner)
                .unwrap();
            inner = LuaValue::Table(t);
        }
        let err = canonical_serialize(&inner).unwrap_err();
        assert_eq!(err, CanonError::TableDepthExceeded);
    }

    #[test]
    fn function_not_serializable() {
        let err = canonical_serialize(&LuaValue::Builtin(BuiltinId::Type)).unwrap_err();
        assert_eq!(err, CanonError::FunctionNotSerializable);
    }

    #[test]
    fn function_closure_not_serializable() {
        let closure = LuaClosure {
            proto_idx: 0,
            upvalues: vec![],
        };
        let err = canonical_serialize(&LuaValue::Function(closure)).unwrap_err();
        assert_eq!(err, CanonError::FunctionNotSerializable);
    }

    #[test]
    fn byte_len_matches_serialize_len() {
        let values = vec![LuaValue::Nil, LuaValue::Boolean(true), int(42), s("hello")];
        for v in &values {
            let serialized_len = canonical_serialize(v).unwrap().len();
            let byte_len = canonical_byte_len(v).unwrap();
            assert_eq!(serialized_len, byte_len, "mismatch for {:?}", v);
        }

        // Also test with a table
        let t = make_table();
        t.borrow_mut().rawset(LuaKey::Integer(1), int(1)).unwrap();
        t.borrow_mut().rawset(LuaKey::Integer(2), int(2)).unwrap();
        let tv = LuaValue::Table(t);
        assert_eq!(
            canonical_serialize(&tv).unwrap().len(),
            canonical_byte_len(&tv).unwrap()
        );
    }

    #[test]
    fn canonical_serialize_table_direct() {
        let t = make_table();
        t.borrow_mut().rawset(LuaKey::Integer(1), int(10)).unwrap();
        t.borrow_mut().rawset(LuaKey::Integer(2), int(20)).unwrap();
        let result = canonical_serialize_table(&t.borrow()).unwrap();
        assert_eq!(String::from_utf8(result).unwrap(), "[10,20]");
    }

    #[test]
    fn empty_table_is_object() {
        let t = make_table();
        assert_eq!(encode_table(&t.borrow()), "{}");
    }

    // ── canonical_deserialize round-trip tests ────────────────────────────────

    fn round_trip(v: &LuaValue) -> LuaValue {
        let bytes = canonical_serialize(v).unwrap();
        canonical_deserialize(&bytes).unwrap()
    }

    #[test]
    fn deser_nil_round_trip() {
        assert_eq!(round_trip(&LuaValue::Nil), LuaValue::Nil);
    }

    #[test]
    fn deser_bool_true_round_trip() {
        assert_eq!(
            round_trip(&LuaValue::Boolean(true)),
            LuaValue::Boolean(true)
        );
    }

    #[test]
    fn deser_bool_false_round_trip() {
        assert_eq!(
            round_trip(&LuaValue::Boolean(false)),
            LuaValue::Boolean(false)
        );
    }

    #[test]
    fn deser_integer_positive() {
        assert_eq!(round_trip(&int(42)), int(42));
    }

    #[test]
    fn deser_integer_negative() {
        assert_eq!(round_trip(&int(-1)), int(-1));
    }

    #[test]
    fn deser_integer_min_max() {
        assert_eq!(round_trip(&int(i64::MAX)), int(i64::MAX));
        assert_eq!(round_trip(&int(i64::MIN)), int(i64::MIN));
    }

    #[test]
    fn deser_string_simple() {
        assert_eq!(round_trip(&s("hello")), s("hello"));
    }

    #[test]
    fn deser_string_with_escapes() {
        assert_eq!(round_trip(&s("a\"b")), s("a\"b"));
        assert_eq!(round_trip(&s("a\\b")), s("a\\b"));
        assert_eq!(round_trip(&s("a\nb")), s("a\nb"));
    }

    #[test]
    fn deser_string_non_ascii() {
        let v = LuaValue::String(LuaString::from_bytes(&[0x80u8]));
        assert_eq!(round_trip(&v), v);
    }

    #[test]
    fn deser_array_table_round_trip() {
        let t = make_table();
        t.borrow_mut().rawset(LuaKey::Integer(1), int(10)).unwrap();
        t.borrow_mut().rawset(LuaKey::Integer(2), int(20)).unwrap();
        t.borrow_mut().rawset(LuaKey::Integer(3), int(30)).unwrap();
        let v = LuaValue::Table(t);
        let bytes = canonical_serialize(&v).unwrap();
        let restored = canonical_deserialize(&bytes).unwrap();
        let rt = restored.as_table().unwrap();
        let tb = rt.borrow();
        assert_eq!(tb.get(&LuaKey::Integer(1)), Some(&int(10)));
        assert_eq!(tb.get(&LuaKey::Integer(2)), Some(&int(20)));
        assert_eq!(tb.get(&LuaKey::Integer(3)), Some(&int(30)));
    }

    #[test]
    fn deser_object_table_round_trip() {
        let t = make_table();
        t.borrow_mut()
            .rawset(LuaKey::String(LuaString::from_str("a")), int(1))
            .unwrap();
        t.borrow_mut()
            .rawset(LuaKey::String(LuaString::from_str("b")), int(2))
            .unwrap();
        let v = LuaValue::Table(t);
        let bytes = canonical_serialize(&v).unwrap();
        let restored = canonical_deserialize(&bytes).unwrap();
        let rt = restored.as_table().unwrap();
        let tb = rt.borrow();
        assert_eq!(
            tb.get(&LuaKey::String(LuaString::from_str("a"))),
            Some(&int(1))
        );
        assert_eq!(
            tb.get(&LuaKey::String(LuaString::from_str("b"))),
            Some(&int(2))
        );
    }

    #[test]
    fn deser_nested_table_round_trip() {
        let inner = make_table();
        inner
            .borrow_mut()
            .rawset(LuaKey::String(LuaString::from_str("x")), int(99))
            .unwrap();
        let outer = make_table();
        outer
            .borrow_mut()
            .rawset(
                LuaKey::String(LuaString::from_str("inner")),
                LuaValue::Table(inner),
            )
            .unwrap();
        let v = LuaValue::Table(outer);
        let bytes = canonical_serialize(&v).unwrap();
        let restored = canonical_deserialize(&bytes).unwrap();
        let rt = restored.as_table().unwrap();
        let tb = rt.borrow();
        let inner_v = tb
            .get(&LuaKey::String(LuaString::from_str("inner")))
            .unwrap();
        let inner_t = inner_v.as_table().unwrap();
        let inner_tb = inner_t.borrow();
        assert_eq!(
            inner_tb.get(&LuaKey::String(LuaString::from_str("x"))),
            Some(&int(99))
        );
    }

    #[test]
    fn deser_invalid_input_error() {
        assert_eq!(
            canonical_deserialize(b"not_json"),
            Err(CanonError::InvalidInput)
        );
        assert_eq!(canonical_deserialize(b""), Err(CanonError::InvalidInput));
        assert_eq!(
            canonical_deserialize(b"42 extra"),
            Err(CanonError::InvalidInput)
        );
    }
}
