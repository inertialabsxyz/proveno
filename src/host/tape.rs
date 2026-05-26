//! Oracle tape for zkVM deterministic replay.
//!
//! Two-phase execution model:
//! 1. **Dry run**: execute with a live `HostInterface` → produces a `Transcript`.
//! 2. **Replay**: construct an `OracleTape` from the transcript, then execute
//!    again with a `TapeHost` that replays recorded responses in order.
//!
//! The replay is bit-for-bit identical to the dry run (same gas, same memory,
//! same return value) without making any external calls, which makes it
//! suitable for execution inside a zkVM guest.

use crate::{
    host::{
        canonicalize::canonical_deserialize,
        poseidon2::{
            bytes_to_fields, field_to_be_bytes32, poseidon2_hash, u8_to_field, u32_to_field,
        },
        transcript::ToolCallRecord,
    },
    types::{table::LuaTable, value::LuaValue},
    vm::engine::HostInterface,
};
#[cfg(not(feature = "std"))]
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec::Vec,
};

// ── TapeEntry ────────────────────────────────────────────────────────────────

/// One entry on the oracle tape — either a successful response payload
/// (canonical JSON bytes) or an error message string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TapeEntry {
    /// Successful tool response: canonical JSON bytes of the response table.
    Ok(Vec<u8>),
    /// Failed tool response: the error message string.
    Err(String),
}

// ── OracleTape ───────────────────────────────────────────────────────────────

/// An ordered sequence of pre-recorded tool responses.
///
/// Constructed from a `Transcript` after a dry run, then handed to
/// `TapeHost` for deterministic replay.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OracleTape {
    pub entries: Vec<TapeEntry>,
}

impl OracleTape {
    pub fn new() -> Self {
        OracleTape {
            entries: Vec::new(),
        }
    }

    /// Build an `OracleTape` from a slice of `ToolCallRecord`s (e.g. from
    /// `Transcript::records()`).
    pub fn from_records(records: &[ToolCallRecord]) -> Self {
        let entries = records
            .iter()
            .map(|r| {
                if r.error_message.is_empty() {
                    TapeEntry::Ok(r.response_canonical.clone())
                } else {
                    TapeEntry::Err(r.error_message.clone())
                }
            })
            .collect();
        OracleTape { entries }
    }

    /// Poseidon2 commitment over all tape entries in order.
    ///
    /// Two-level hash: each entry is hashed individually into a leaf Field
    /// element, then the concatenated leaves are hashed once more:
    ///
    /// ```text
    ///     leaf_i      = Poseidon2( tag, len, payload_byte_0, ..., payload_byte_{m-1} )
    ///     commitment  = Poseidon2( leaf_0, leaf_1, ..., leaf_{n-1} )
    /// ```
    ///
    /// Per-entry encoding (as Field elements, one byte per field):
    /// - 1 Field: tag (`0x00` = Ok, `0x01` = Err)
    /// - 1 Field: payload length in bytes
    /// - 1 Field per payload byte
    ///
    /// The two-level structure matches the Noir circuit, which feeds the same
    /// (tag, len, payload-as-fields) tuple into `Poseidon2::hash` and then
    /// hashes the resulting leaves together for the outer commitment. Each
    /// hash output is a BN254 Field element; it is returned here as 32-byte
    /// big-endian so the public-input wire shape stays `[u8; 32]`.
    ///
    /// An empty tape commits to `Poseidon2([])` — a fixed sponge-IV-only
    /// digest derived from the zero-length domain separator.
    pub fn commitment_hash(&self) -> [u8; 32] {
        let leaves: Vec<_> = self
            .entries
            .iter()
            .map(|entry| {
                let (tag, payload): (u8, &[u8]) = match entry {
                    TapeEntry::Ok(bytes) => (0x00, bytes.as_slice()),
                    TapeEntry::Err(msg) => (0x01, msg.as_bytes()),
                };
                let mut inputs = Vec::with_capacity(2 + payload.len());
                inputs.push(u8_to_field(tag));
                inputs.push(u32_to_field(payload.len() as u32));
                inputs.extend(bytes_to_fields(payload));
                poseidon2_hash(&inputs)
            })
            .collect();
        field_to_be_bytes32(poseidon2_hash(&leaves))
    }

    /// Hex-encoded Poseidon2 commitment hash (64 lowercase hex chars).
    pub fn commitment_hash_hex(&self) -> String {
        self.commitment_hash()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── TapeHost ─────────────────────────────────────────────────────────────────

/// A `HostInterface` that replays responses from an `OracleTape`.
///
/// Each call to `call_tool` consumes the next entry from the tape:
/// - `TapeEntry::Ok(bytes)` — deserializes the JSON bytes back into a
///   `LuaTable` and returns `Ok(table)`.
/// - `TapeEntry::Err(msg)` — returns `Err(msg)`.
///
/// If the tape is exhausted (more calls than entries), an error is returned.
pub struct TapeHost {
    tape: OracleTape,
    cursor: usize,
}

impl TapeHost {
    pub fn new(tape: OracleTape) -> Self {
        TapeHost { tape, cursor: 0 }
    }

    /// Number of entries remaining on the tape.
    pub fn remaining(&self) -> usize {
        self.tape.entries.len().saturating_sub(self.cursor)
    }

    /// Whether all tape entries have been consumed.
    pub fn is_exhausted(&self) -> bool {
        self.cursor >= self.tape.entries.len()
    }
}

impl HostInterface for TapeHost {
    fn call_tool(&mut self, _name: &str, _args: &LuaTable) -> Result<LuaTable, String> {
        if self.cursor >= self.tape.entries.len() {
            return Err("oracle tape exhausted".to_owned());
        }
        let entry = &self.tape.entries[self.cursor];
        self.cursor += 1;

        match entry {
            TapeEntry::Ok(bytes) => {
                let value = canonical_deserialize(bytes)
                    .map_err(|e| format!("tape decode error: {e:?}"))?;
                match value {
                    LuaValue::Table(t) => Ok(t.borrow().clone()),
                    _ => Err(format!(
                        "tape entry is not a table (got {:?})",
                        value.type_name()
                    )),
                }
            }
            TapeEntry::Err(msg) => Err(msg.clone()),
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        host::transcript::{ToolCallStatus, Transcript},
        types::{table::LuaKey, value::LuaString},
    };

    fn ok_record(seq: usize, response_json: &[u8]) -> ToolCallRecord {
        ToolCallRecord {
            seq,
            tool_name: "tool".to_owned(),
            args_canonical: b"{}".to_vec(),
            args_bytes: 2,
            response_hash: "".to_owned(),
            response_bytes: response_json.len(),
            response_canonical: response_json.to_vec(),
            error_message: String::new(),
            gas_charged: 100,
            status: ToolCallStatus::Ok,
        }
    }

    fn err_record(seq: usize, msg: &str) -> ToolCallRecord {
        ToolCallRecord {
            seq,
            tool_name: "tool".to_owned(),
            args_canonical: b"{}".to_vec(),
            args_bytes: 2,
            response_hash: String::new(),
            response_bytes: 0,
            response_canonical: Vec::new(),
            error_message: msg.to_owned(),
            gas_charged: 0,
            status: ToolCallStatus::Error,
        }
    }

    // ── OracleTape::from_records ──────────────────────────────────────────────

    #[test]
    fn from_records_empty() {
        let tape = OracleTape::from_records(&[]);
        assert!(tape.is_empty());
        assert_eq!(tape.len(), 0);
    }

    #[test]
    fn from_records_ok_entry() {
        let r = ok_record(0, b"{\"x\":1}");
        let tape = OracleTape::from_records(&[r]);
        assert_eq!(tape.len(), 1);
        assert_eq!(tape.entries[0], TapeEntry::Ok(b"{\"x\":1}".to_vec()));
    }

    #[test]
    fn from_records_err_entry() {
        let r = err_record(0, "something failed");
        let tape = OracleTape::from_records(&[r]);
        assert_eq!(tape.len(), 1);
        assert_eq!(
            tape.entries[0],
            TapeEntry::Err("something failed".to_owned())
        );
    }

    #[test]
    fn from_records_mixed() {
        let records = vec![
            ok_record(0, b"{\"a\":1}"),
            err_record(1, "oops"),
            ok_record(2, b"{\"b\":2}"),
        ];
        let tape = OracleTape::from_records(&records);
        assert_eq!(tape.len(), 3);
        assert!(matches!(&tape.entries[0], TapeEntry::Ok(_)));
        assert!(matches!(&tape.entries[1], TapeEntry::Err(_)));
        assert!(matches!(&tape.entries[2], TapeEntry::Ok(_)));
    }

    // ── OracleTape::commitment_hash ───────────────────────────────────────────

    #[test]
    fn commitment_hash_is_32_bytes() {
        let tape = OracleTape::from_records(&[ok_record(0, b"{}")]);
        let h = tape.commitment_hash();
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn commitment_hash_hex_is_64_hex_chars() {
        let tape = OracleTape::from_records(&[ok_record(0, b"{}")]);
        let h = tape.commitment_hash_hex();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn commitment_hash_empty_tape_is_deterministic() {
        let h1 = OracleTape::new().commitment_hash();
        let h2 = OracleTape::new().commitment_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn commitment_hash_differs_for_different_entries() {
        let t1 = OracleTape::from_records(&[ok_record(0, b"{\"a\":1}")]);
        let t2 = OracleTape::from_records(&[ok_record(0, b"{\"a\":2}")]);
        assert_ne!(t1.commitment_hash(), t2.commitment_hash());
    }

    #[test]
    fn commitment_hash_ok_vs_err_differs() {
        let t_ok = OracleTape::from_records(&[ok_record(0, b"\"msg\"")]);
        let t_err = OracleTape::from_records(&[err_record(0, "msg")]);
        assert_ne!(t_ok.commitment_hash(), t_err.commitment_hash());
    }

    // ── TapeHost ─────────────────────────────────────────────────────────────

    fn empty_args() -> LuaTable {
        LuaTable::new()
    }

    #[test]
    fn tape_host_replays_ok_entry() {
        let tape = OracleTape::from_records(&[ok_record(0, b"{\"result\":42}")]);
        let mut host = TapeHost::new(tape);
        let t = host.call_tool("anything", &empty_args()).unwrap();
        let key = LuaKey::String(LuaString::from_str("result"));
        assert_eq!(t.get(&key), Some(&LuaValue::Integer(42)));
    }

    #[test]
    fn tape_host_replays_err_entry() {
        let tape = OracleTape::from_records(&[err_record(0, "tool failed")]);
        let mut host = TapeHost::new(tape);
        let err = host.call_tool("anything", &empty_args()).unwrap_err();
        assert_eq!(err, "tool failed");
    }

    #[test]
    fn tape_host_exhausted_returns_error() {
        let tape = OracleTape::new();
        let mut host = TapeHost::new(tape);
        let err = host.call_tool("x", &empty_args()).unwrap_err();
        assert!(err.contains("exhausted"));
    }

    #[test]
    fn tape_host_advances_cursor() {
        let records = vec![ok_record(0, b"{\"n\":1}"), ok_record(1, b"{\"n\":2}")];
        let tape = OracleTape::from_records(&records);
        let mut host = TapeHost::new(tape);
        assert_eq!(host.remaining(), 2);

        let t1 = host.call_tool("t", &empty_args()).unwrap();
        assert_eq!(host.remaining(), 1);
        assert!(!host.is_exhausted());

        let t2 = host.call_tool("t", &empty_args()).unwrap();
        assert_eq!(host.remaining(), 0);
        assert!(host.is_exhausted());

        let k = LuaKey::String(LuaString::from_str("n"));
        assert_eq!(t1.get(&k), Some(&LuaValue::Integer(1)));
        assert_eq!(t2.get(&k), Some(&LuaValue::Integer(2)));
    }

    #[test]
    fn tape_host_ignores_tool_name_and_args() {
        // TapeHost is positional — tool name/args don't affect which entry is returned.
        let tape = OracleTape::from_records(&[ok_record(0, b"{\"v\":99}")]);
        let mut host = TapeHost::new(tape);
        let mut different_args = LuaTable::new();
        different_args
            .rawset(
                LuaKey::String(LuaString::from_str("q")),
                LuaValue::Integer(1),
            )
            .unwrap();
        let t = host
            .call_tool("completely_different_tool", &different_args)
            .unwrap();
        let k = LuaKey::String(LuaString::from_str("v"));
        assert_eq!(t.get(&k), Some(&LuaValue::Integer(99)));
    }

    // ── Transcript → OracleTape round-trip (unit level) ──────────────────────

    #[test]
    fn transcript_to_tape_preserves_entry_count() {
        let mut transcript = Transcript::new();
        transcript.record_ok("t1", b"{}".to_vec(), b"{\"a\":1}".to_vec(), 100);
        transcript.record_ok("t2", b"{}".to_vec(), b"{\"b\":2}".to_vec(), 100);
        let tape = OracleTape::from_records(transcript.records());
        assert_eq!(tape.len(), 2);
    }

    #[test]
    fn transcript_error_becomes_tape_err_entry() {
        let mut transcript = Transcript::new();
        transcript.record_error("broken", b"{}".to_vec(), 0, "it broke");
        let tape = OracleTape::from_records(transcript.records());
        assert_eq!(tape.entries[0], TapeEntry::Err("it broke".to_owned()));
    }
}
