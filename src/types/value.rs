#[cfg(feature = "std")]
use std::{cell::RefCell, rc::Rc, sync::Arc};
#[cfg(not(feature = "std"))]
use {
    alloc::{
        rc::Rc,
        string::{String, ToString},
        sync::Arc,
        vec::Vec,
    },
    core::cell::RefCell,
};

use crate::types::table::{LuaKey, LuaTable};
pub const MAX_TABLE_ENTRIES: usize = 50_000;

#[derive(Debug)]
pub enum LuaError {
    Runtime,
    Memory,
    Type,
}

/// Identifies a built-in standard library function by a stable tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BuiltinId {
    // Core
    Type,
    Tostring,
    Tonumber,
    Select,
    Unpack,
    // string module
    StringLen,
    StringSub,
    StringFind,
    StringFindLiteral,
    StringUpper,
    StringLower,
    StringRep,
    StringByte,
    StringChar,
    StringFormat,
    StringUnsupported, // match/gmatch/gsub sentinel
    // math module
    MathAbs,
    MathMin,
    MathMax,
    MathScaleDiv,
    // table module
    TableInsert,
    TableRemove,
    TableConcat,
    TableSort,
    TableMove,
    // json module
    JsonEncode,
    JsonDecode,
    JsonDecodeStrings,
}

/// A Lua closure: a function prototype index plus captured upvalues.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LuaClosure {
    pub proto_idx: usize,
    #[cfg_attr(feature = "serde", serde(skip))]
    pub upvalues: Vec<Rc<RefCell<LuaValue>>>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LuaString(Arc<[u8]>);

impl core::fmt::Debug for LuaString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "\"{}\"", String::from_utf8_lossy(&self.0))
    }
}

impl LuaString {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        LuaString(Arc::from(bytes))
    }

    pub fn from_str(s: &str) -> Self {
        LuaString(Arc::from(s.as_bytes()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug, Clone)]
pub enum LuaValue {
    Nil,
    Boolean(bool),
    Integer(i64),
    String(LuaString),
    Table(Rc<RefCell<LuaTable>>),
    Function(LuaClosure),
    Builtin(BuiltinId),
}

impl LuaValue {
    pub fn type_name(&self) -> &'static str {
        match self {
            LuaValue::Nil => "nil",
            LuaValue::Boolean(_) => "boolean",
            LuaValue::Integer(_) => "integer",
            LuaValue::String(_) => "string",
            LuaValue::Table(_) => "table",
            LuaValue::Function(_) | LuaValue::Builtin(_) => "function",
        }
    }
}

impl LuaValue {
    pub fn is_truthy(&self) -> bool {
        !matches!(self, LuaValue::Nil | LuaValue::Boolean(false))
    }
}

impl PartialEq for LuaValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (LuaValue::Nil, LuaValue::Nil) => true,
            (LuaValue::Boolean(a), LuaValue::Boolean(b)) => a == b,
            (LuaValue::Integer(a), LuaValue::Integer(b)) => a == b,
            (LuaValue::String(a), LuaValue::String(b)) => a == b,
            (LuaValue::Table(a), LuaValue::Table(b)) => Rc::ptr_eq(a, b),
            (LuaValue::Function(a), LuaValue::Function(b)) => {
                a.proto_idx == b.proto_idx
                    && a.upvalues.len() == b.upvalues.len()
                    && a.upvalues
                        .iter()
                        .zip(b.upvalues.iter())
                        .all(|(x, y)| Rc::ptr_eq(x, y))
            }
            (LuaValue::Builtin(a), LuaValue::Builtin(b)) => a == b,
            _ => false,
        }
    }
}

impl LuaValue {
    /// Returns Ok(Ordering) if the two values support comparison.
    /// Returns Err(LuaError(Type)) otherwise.
    pub fn lua_cmp(&self, other: &Self) -> Result<core::cmp::Ordering, LuaError> {
        match (self, other) {
            (LuaValue::Integer(a), LuaValue::Integer(b)) => Ok(a.cmp(b)),
            (LuaValue::String(a), LuaValue::String(b)) => Ok(a.cmp(b)),
            _ => Err(LuaError::Type),
        }
    }
}

impl LuaValue {
    pub fn as_integer(&self) -> Result<i64, LuaError> {
        match self {
            LuaValue::Integer(n) => Ok(*n),
            _ => Err(LuaError::Type),
        }
    }

    pub fn as_string(&self) -> Result<&LuaString, LuaError> {
        match self {
            LuaValue::String(s) => Ok(s),
            _ => Err(LuaError::Type),
        }
    }

    pub fn as_table(&self) -> Result<Rc<RefCell<LuaTable>>, LuaError> {
        match self {
            LuaValue::Table(t) => Ok(Rc::clone(t)),
            _ => Err(LuaError::Type),
        }
    }

    pub fn as_function(&self) -> Result<&LuaClosure, LuaError> {
        match self {
            LuaValue::Function(f) => Ok(f),
            _ => Err(LuaError::Type),
        }
    }

    pub fn as_bool(&self) -> Result<bool, LuaError> {
        match self {
            LuaValue::Boolean(b) => Ok(*b),
            _ => Err(LuaError::Type),
        }
    }
}

impl LuaValue {
    pub fn to_number_coerce(&self) -> LuaValue {
        match self {
            LuaValue::Integer(_) => self.clone(),
            LuaValue::String(s) => String::from_utf8_lossy(s.as_bytes())
                .trim()
                .parse()
                .map_or(LuaValue::Nil, |n| LuaValue::Integer(n)),
            _ => LuaValue::Nil,
        }
    }
}

impl LuaValue {
    pub fn to_lua_string(&self) -> LuaString {
        match self {
            LuaValue::Nil => LuaString::from_str("nil"),
            LuaValue::Boolean(b) => LuaString::from_str(if *b { "true" } else { "false" }),
            LuaValue::Integer(n) => LuaString::from_str(&n.to_string()),
            LuaValue::String(s) => s.clone(),
            LuaValue::Table(_) => LuaString::from_str("table"),
            LuaValue::Function(_) | LuaValue::Builtin(_) => LuaString::from_str("function"),
        }
    }
}

impl LuaValue {
    pub fn lua_len(&self) -> Result<Self, LuaError> {
        match self {
            LuaValue::String(s) => Ok(LuaValue::Integer(s.len() as i64)),
            LuaValue::Table(t) => Ok(LuaValue::Integer(t.borrow().length())),
            _ => Err(LuaError::Type),
        }
    }
}
impl LuaValue {
    pub fn into_key(self) -> Result<LuaKey, LuaError> {
        match self {
            LuaValue::Integer(n) => Ok(LuaKey::Integer(n)),
            LuaValue::String(s) => Ok(LuaKey::String(s)),
            LuaValue::Boolean(b) => Ok(LuaKey::Boolean(b)),
            LuaValue::Nil => Err(LuaError::Runtime),
            LuaValue::Table(_) | LuaValue::Function(_) | LuaValue::Builtin(_) => {
                Err(LuaError::Type)
            }
        }
    }
}

impl From<LuaKey> for LuaValue {
    fn from(k: LuaKey) -> Self {
        match k {
            LuaKey::Integer(n) => LuaValue::Integer(n),
            LuaKey::String(s) => LuaValue::String(s),
            LuaKey::Boolean(b) => LuaValue::Boolean(b),
        }
    }
}

impl core::fmt::Display for LuaValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LuaValue::Nil => write!(f, "nil"),
            LuaValue::Boolean(b) => write!(f, "{}", b),
            LuaValue::Integer(n) => write!(f, "{}", n),
            LuaValue::String(s) => write!(f, "{}", String::from_utf8_lossy(s.as_bytes())),
            LuaValue::Table(_) => write!(f, "table"),
            LuaValue::Function(_) | LuaValue::Builtin(_) => write!(f, "function"),
        }
    }
}

impl LuaValue {
    pub fn lua_concat(&self, rhs: &Self) -> Result<Self, LuaError> {
        let left = match self {
            LuaValue::String(s) => s.clone(),
            LuaValue::Integer(n) => LuaString::from_str(&n.to_string()),
            _ => return Err(LuaError::Type),
        };
        let right = match rhs {
            LuaValue::String(s) => s.clone(),
            LuaValue::Integer(n) => LuaString::from_str(&n.to_string()),
            _ => return Err(LuaError::Type),
        };
        let total_len = left.len() + right.len();
        if total_len > 65536 {
            return Err(LuaError::Memory);
        }
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(left.as_bytes());
        buf.extend_from_slice(right.as_bytes());
        Ok(LuaValue::String(LuaString(Arc::from(buf.as_slice()))))
    }
}

impl LuaValue {
    pub fn lua_add(&self, rhs: &Self) -> Result<Self, LuaError> {
        let a = self.as_integer()?;
        let b = rhs.as_integer()?;
        Ok(LuaValue::Integer(a.wrapping_add(b)))
    }
    pub fn lua_sub(&self, rhs: &Self) -> Result<Self, LuaError> {
        let a = self.as_integer()?;
        let b = rhs.as_integer()?;
        Ok(LuaValue::Integer(a.wrapping_sub(b)))
    }
    pub fn lua_mul(&self, rhs: &Self) -> Result<Self, LuaError> {
        let a = self.as_integer()?;
        let b = rhs.as_integer()?;
        Ok(LuaValue::Integer(a.wrapping_mul(b)))
    }
    pub fn lua_idiv(&self, rhs: &Self) -> Result<Self, LuaError> {
        let a = self.as_integer()?;
        let b = rhs.as_integer()?;
        if b == 0 {
            return Err(LuaError::Runtime);
        }
        // Rust's `/` truncates; floor division: adjust when signs differ and remainder nonzero.
        let d = a.wrapping_div(b);
        let r = a.wrapping_rem(b);
        if (r != 0) && ((r < 0) != (b < 0)) {
            Ok(LuaValue::Integer(d.wrapping_sub(1)))
        } else {
            Ok(LuaValue::Integer(d))
        }
    }
    pub fn lua_mod(&self, rhs: &Self) -> Result<Self, LuaError> {
        let a = self.as_integer()?;
        let b = rhs.as_integer()?;
        if b == 0 {
            return Err(LuaError::Runtime);
        }
        let r = a.wrapping_rem(b);
        if (r != 0) && ((r < 0) != (b < 0)) {
            Ok(LuaValue::Integer(r.wrapping_add(b)))
        } else {
            Ok(LuaValue::Integer(r))
        }
    }
    pub fn lua_unm(&self) -> Result<Self, LuaError> {
        Ok(LuaValue::Integer(self.as_integer()?.wrapping_neg()))
    }
}

// ── Serde impls ────────────────────────────────────────────────────────────────

#[cfg(feature = "serde")]
mod serde_impls {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    // ── LuaString ─────────────────────────────────────────────────────────────

    impl Serialize for LuaString {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(self.as_bytes())
        }
    }

    impl<'de> Deserialize<'de> for LuaString {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct BytesVisitor;
            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = LuaString;
                fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                    write!(f, "byte sequence")
                }
                fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<LuaString, E> {
                    Ok(LuaString::from_bytes(v))
                }
                fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<LuaString, E> {
                    Ok(LuaString::from_bytes(&v))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<LuaString, A::Error> {
                    let mut bytes = Vec::new();
                    while let Some(b) = seq.next_element::<u8>()? {
                        bytes.push(b);
                    }
                    Ok(LuaString::from_bytes(&bytes))
                }
            }
            d.deserialize_bytes(BytesVisitor)
        }
    }

    // ── LuaValue ──────────────────────────────────────────────────────────────

    /// Helper enum that mirrors LuaValue but without Rc<RefCell<>> wrappers.
    /// Used to drive serde derive for LuaValue serialization.
    #[derive(Serialize, Deserialize)]
    enum LuaValueHelper {
        Nil,
        Boolean(bool),
        Integer(i64),
        String(LuaString),
        Table(LuaTable),
    }

    impl Serialize for LuaValue {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let helper = match self {
                LuaValue::Nil => LuaValueHelper::Nil,
                LuaValue::Boolean(b) => LuaValueHelper::Boolean(*b),
                LuaValue::Integer(n) => LuaValueHelper::Integer(*n),
                LuaValue::String(st) => LuaValueHelper::String(st.clone()),
                LuaValue::Table(t) => LuaValueHelper::Table(t.borrow().clone()),
                LuaValue::Function(_) | LuaValue::Builtin(_) => {
                    return Err(serde::ser::Error::custom("functions cannot be serialized"));
                }
            };
            helper.serialize(s)
        }
    }

    impl<'de> Deserialize<'de> for LuaValue {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let helper = LuaValueHelper::deserialize(d)?;
            Ok(match helper {
                LuaValueHelper::Nil => LuaValue::Nil,
                LuaValueHelper::Boolean(b) => LuaValue::Boolean(b),
                LuaValueHelper::Integer(n) => LuaValue::Integer(n),
                LuaValueHelper::String(st) => LuaValue::String(st),
                LuaValueHelper::Table(t) => LuaValue::Table(Rc::new(RefCell::new(t))),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::table::LuaTable;

    fn int(n: i64) -> LuaValue {
        LuaValue::Integer(n)
    }

    fn s(text: &str) -> LuaValue {
        LuaValue::String(LuaString::from_str(text))
    }

    fn ls(text: &str) -> LuaString {
        LuaString::from_str(text)
    }

    fn make_table() -> LuaValue {
        LuaValue::Table(Rc::new(RefCell::new(LuaTable::new())))
    }

    // --- type_name ---

    #[test]
    fn type_name_all_variants() {
        assert_eq!(LuaValue::Nil.type_name(), "nil");
        assert_eq!(LuaValue::Boolean(true).type_name(), "boolean");
        assert_eq!(int(0).type_name(), "integer");
        assert_eq!(s("").type_name(), "string");
        assert_eq!(make_table().type_name(), "table");
        assert_eq!(
            LuaValue::Function(LuaClosure {
                proto_idx: 0,
                upvalues: vec![]
            })
            .type_name(),
            "function"
        );
        assert_eq!(LuaValue::Builtin(BuiltinId::Type).type_name(), "function");
    }

    // --- is_truthy ---

    #[test]
    fn truthiness() {
        assert!(!LuaValue::Nil.is_truthy());
        assert!(!LuaValue::Boolean(false).is_truthy());
        assert!(LuaValue::Boolean(true).is_truthy());
        assert!(int(0).is_truthy());
        assert!(s("").is_truthy());
        assert!(make_table().is_truthy());
    }

    // --- PartialEq ---

    #[test]
    fn eq_integers() {
        assert_eq!(int(42), int(42));
        assert_ne!(int(1), int(2));
    }

    #[test]
    fn eq_strings_by_bytes() {
        assert_eq!(s("hello"), s("hello"));
        assert_ne!(s("hello"), s("world"));
        // Different byte values even if same chars
        let a = LuaValue::String(LuaString(Arc::from("abc".as_bytes())));
        let b = LuaValue::String(LuaString(Arc::from("abc".as_bytes())));
        assert_eq!(a, b);
    }

    #[test]
    fn eq_tables_reference_identity() {
        let t1 = make_table();
        let t2 = make_table(); // separate allocation
        assert_ne!(t1, t2);
        // Clone shares the Rc — same identity
        assert_eq!(t1, t1.clone());
    }

    #[test]
    fn eq_cross_type_never_equal() {
        assert_ne!(int(0), LuaValue::Boolean(false));
        assert_ne!(s(""), LuaValue::Nil);
        assert_ne!(int(1), LuaValue::Boolean(true));
    }

    // --- lua_cmp ---

    #[test]
    fn cmp_integers() {
        use std::cmp::Ordering;
        assert_eq!(int(1).lua_cmp(&int(2)).unwrap(), Ordering::Less);
        assert_eq!(int(2).lua_cmp(&int(2)).unwrap(), Ordering::Equal);
        assert_eq!(int(3).lua_cmp(&int(2)).unwrap(), Ordering::Greater);
    }

    #[test]
    fn cmp_strings_lexicographic() {
        use std::cmp::Ordering;
        assert_eq!(s("abc").lua_cmp(&s("abd")).unwrap(), Ordering::Less);
        assert_eq!(s("abc").lua_cmp(&s("abc")).unwrap(), Ordering::Equal);
        assert_eq!(s("b").lua_cmp(&s("a")).unwrap(), Ordering::Greater);
    }

    #[test]
    fn cmp_mixed_type_is_err_type() {
        assert!(matches!(int(1).lua_cmp(&s("1")), Err(LuaError::Type)));
    }

    // --- lua_add ---

    #[test]
    fn add_basic() {
        assert_eq!(int(3).lua_add(&int(4)).unwrap(), int(7));
    }

    #[test]
    fn add_wraps_on_overflow() {
        assert_eq!(int(i64::MAX).lua_add(&int(1)).unwrap(), int(i64::MIN));
    }

    // --- lua_sub ---

    #[test]
    fn sub_wrapping() {
        assert_eq!(int(i64::MIN).lua_sub(&int(1)).unwrap(), int(i64::MAX));
    }

    // --- lua_mul ---

    #[test]
    fn mul_wrapping() {
        assert_eq!(int(i64::MAX).lua_mul(&int(2)).unwrap(), int(-2));
    }

    // --- lua_idiv ---

    #[test]
    fn idiv_positive() {
        assert_eq!(int(7).lua_idiv(&int(2)).unwrap(), int(3));
    }

    #[test]
    fn idiv_negative_numerator() {
        assert_eq!(int(-7).lua_idiv(&int(2)).unwrap(), int(-4));
    }

    #[test]
    fn idiv_negative_denominator() {
        assert_eq!(int(7).lua_idiv(&int(-2)).unwrap(), int(-4));
    }

    #[test]
    fn idiv_by_zero() {
        assert!(matches!(int(7).lua_idiv(&int(0)), Err(LuaError::Runtime)));
    }

    // --- lua_mod ---

    #[test]
    fn mod_positive() {
        assert_eq!(int(7).lua_mod(&int(3)).unwrap(), int(1));
    }

    #[test]
    fn mod_negative_numerator_lua_semantics() {
        // Lua: -7 % 3 == 2  (not -1 as in C)
        assert_eq!(int(-7).lua_mod(&int(3)).unwrap(), int(2));
    }

    #[test]
    fn mod_negative_denominator_lua_semantics() {
        // Lua: 7 % -3 == -2  (not 1 as in C)
        assert_eq!(int(7).lua_mod(&int(-3)).unwrap(), int(-2));
    }

    #[test]
    fn mod_by_zero() {
        assert!(matches!(int(7).lua_mod(&int(0)), Err(LuaError::Runtime)));
    }

    // --- lua_unm ---

    #[test]
    fn unm_basic() {
        assert_eq!(int(5).lua_unm().unwrap(), int(-5));
        assert_eq!(int(-5).lua_unm().unwrap(), int(5));
    }

    #[test]
    fn unm_min_wraps() {
        assert_eq!(int(i64::MIN).lua_unm().unwrap(), int(i64::MIN));
    }

    // --- lua_concat ---

    #[test]
    fn concat_strings() {
        assert_eq!(s("foo").lua_concat(&s("bar")).unwrap(), s("foobar"));
    }

    #[test]
    fn concat_integer_coercion() {
        assert_eq!(int(42).lua_concat(&s("!")).unwrap(), s("42!"));
    }

    #[test]
    fn concat_nil_is_err_type() {
        assert!(matches!(
            LuaValue::Nil.lua_concat(&s("x")),
            Err(LuaError::Type)
        ));
    }

    #[test]
    fn concat_result_over_max_len_is_err_mem() {
        let big = LuaValue::String(LuaString(Arc::from(vec![b'a'; 40000].as_slice())));
        let also_big = LuaValue::String(LuaString(Arc::from(vec![b'b'; 40000].as_slice())));
        assert!(matches!(big.lua_concat(&also_big), Err(LuaError::Memory)));
    }

    // --- lua_len ---

    #[test]
    fn len_string_byte_count() {
        assert_eq!(s("hello").lua_len().unwrap(), int(5));
        // Multi-byte: len is bytes, not chars
        let bytes = LuaValue::String(LuaString(Arc::from(&[0xc3u8, 0xa9][..])));
        assert_eq!(bytes.lua_len().unwrap(), int(2));
    }

    #[test]
    fn len_table_array_border() {
        let tval = make_table();
        if let LuaValue::Table(ref t) = tval {
            t.borrow_mut().rawset(LuaKey::Integer(1), int(10)).unwrap();
            t.borrow_mut().rawset(LuaKey::Integer(2), int(20)).unwrap();
        }
        assert_eq!(tval.lua_len().unwrap(), int(2));
    }

    #[test]
    fn len_nil_is_err_type() {
        assert!(matches!(LuaValue::Nil.lua_len(), Err(LuaError::Type)));
    }

    // --- to_lua_string ---

    #[test]
    fn to_lua_string_all_variants() {
        assert_eq!(LuaValue::Nil.to_lua_string(), ls("nil"));
        assert_eq!(LuaValue::Boolean(true).to_lua_string(), ls("true"));
        assert_eq!(LuaValue::Boolean(false).to_lua_string(), ls("false"));
        assert_eq!(int(-42).to_lua_string(), ls("-42"));
        assert_eq!(s("hello").to_lua_string(), ls("hello"));
        assert_eq!(make_table().to_lua_string(), ls("table"));
        assert_eq!(
            LuaValue::Function(LuaClosure {
                proto_idx: 0,
                upvalues: vec![]
            })
            .to_lua_string(),
            ls("function")
        );
        assert_eq!(
            LuaValue::Builtin(BuiltinId::Type).to_lua_string(),
            ls("function")
        );
    }

    // --- to_number_coerce ---

    #[test]
    fn to_number_coerce_string_decimal() {
        assert_eq!(s("42").to_number_coerce(), int(42));
    }

    #[test]
    fn to_number_coerce_trims_whitespace() {
        assert_eq!(s("  -7  ").to_number_coerce(), int(-7));
    }

    #[test]
    fn to_number_coerce_float_string_is_nil() {
        assert_eq!(s("3.14").to_number_coerce(), LuaValue::Nil);
    }

    #[test]
    fn to_number_coerce_integer_passthrough() {
        assert_eq!(int(5).to_number_coerce(), int(5));
    }

    // --- into_key ---

    #[test]
    fn into_key_nil_is_err_runtime() {
        assert!(matches!(LuaValue::Nil.into_key(), Err(LuaError::Runtime)));
    }

    #[test]
    fn into_key_table_is_err_type() {
        assert!(matches!(make_table().into_key(), Err(LuaError::Type)));
    }

    // --- LuaString ---

    #[test]
    fn lua_string_over_max_len() {
        // from_bytes currently infallible; this test will guide adding the length check
        let big = vec![0u8; 65537];
        // When the 64KB cap is enforced, this should return Err(LuaError::Memory).
        // For now it succeeds — this test documents the expected future behaviour.
        let result = std::panic::catch_unwind(|| LuaString::from_bytes(&big));
        // Currently succeeds (no cap yet); mark as expected to change:
        assert!(
            result.is_ok(),
            "from_bytes should not panic; cap enforcement pending"
        );
    }

    #[test]
    fn lua_string_ordering_by_bytes() {
        assert!(ls("abc") < ls("abd"));
        assert!(ls("a") < ls("b"));
        assert!(ls("abc") < ls("abcd"));
        assert_eq!(ls("xyz"), ls("xyz"));
    }
}
