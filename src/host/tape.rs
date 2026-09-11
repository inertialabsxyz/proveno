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

#[cfg(feature = "poseidon")]
use crate::host::poseidon2::{
    bytes_to_fields, field_to_be_bytes32, poseidon2_hash, u8_to_field, u32_to_field,
};
use crate::{
    host::{canonicalize::canonical_deserialize, transcript::ToolCallRecord},
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
use sha2::{Digest, Sha256};

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
    /// Per-entry provenance attestation blobs, positionally aligned with
    /// `entries` (empty blob = no attestation). Carried alongside `entries`
    /// rather than inside `TapeEntry` so the existing `tool_responses_hash`
    /// commitment and `TapeHost` replay are unchanged — the program never sees
    /// attestations; only `attestation_commitment()` binds them.
    #[cfg_attr(feature = "serde", serde(default))]
    pub attestations: Vec<Vec<u8>>,
}

impl OracleTape {
    pub fn new() -> Self {
        OracleTape {
            entries: Vec::new(),
            attestations: Vec::new(),
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
        let attestations = records.iter().map(|r| r.attestation.clone()).collect();
        OracleTape {
            entries,
            attestations,
        }
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
    #[cfg(feature = "poseidon")]
    pub fn commitment_hash(&self) -> [u8; 32] {
        let leaves: Vec<_> = self
            .entries
            .iter()
            .map(|entry| {
                let (tag, payload) = Self::entry_parts(entry);
                Self::response_leaf(tag, payload)
            })
            .collect();
        field_to_be_bytes32(poseidon2_hash(&leaves))
    }

    /// Hex-encoded Poseidon2 commitment hash (64 lowercase hex chars).
    #[cfg(feature = "poseidon")]
    pub fn commitment_hash_hex(&self) -> String {
        self.commitment_hash()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Per-entry response leaf — `Poseidon2(tag, len, payload_bytes...)`.
    ///
    /// This is exactly the leaf `commitment_hash` builds for the tool-responses
    /// commitment. `attestation_commitment` reuses it so the provenance bind is
    /// provably over the *same* response bytes that `tool_responses_hash`
    /// commits to — the circuit computes this leaf once and feeds both hashes.
    #[cfg(feature = "poseidon")]
    fn response_leaf(tag: u8, payload: &[u8]) -> crate::host::poseidon2::FieldElement {
        let mut inputs = Vec::with_capacity(2 + payload.len());
        inputs.push(u8_to_field(tag));
        inputs.push(u32_to_field(payload.len() as u32));
        inputs.extend(bytes_to_fields(payload));
        poseidon2_hash(&inputs)
    }

    /// Bind-only provenance commitment: welds each response leaf to the
    /// provenance attestation the host sourced for it, per call, in order.
    ///
    /// Nested two-level Poseidon2. Each entry binds its response leaf (identical
    /// to the `commitment_hash` leaf) to an attestation leaf, then the bound
    /// leaves are hashed together:
    ///
    /// ```text
    ///     resp_leaf_i  = Poseidon2( tag, resp_len, resp_bytes... )
    ///     att_leaf_i   = Poseidon2( att_len, att_bytes... )
    ///     bound_leaf_i = Poseidon2( resp_leaf_i, att_leaf_i )
    ///     commitment   = Poseidon2( bound_leaf_0, ..., bound_leaf_{n-1} )
    /// ```
    ///
    /// The nesting (rather than one flat absorb of response ‖ attestation) keeps
    /// each sub-hash a fixed-shape, padded buffer hashed with a `message_size` —
    /// the pattern the Noir circuit uses — so no dynamic-offset indexing is
    /// needed to recompute it in-circuit.
    ///
    /// This is "bind", not "verify": the attestation bytes are committed, not
    /// checked. A downstream consumer that trusts the provider verifies the
    /// attestation against the response it covers. Unattested calls (empty blob)
    /// still produce a stable `att_leaf` over `att_len = 0`, so the commitment
    /// is well-defined whether or not provenance is present.
    ///
    /// An empty tape commits to `Poseidon2([])`, matching `commitment_hash`.
    #[cfg(feature = "poseidon")]
    pub fn attestation_commitment(&self) -> [u8; 32] {
        let leaves: Vec<_> = self
            .entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let (tag, payload) = Self::entry_parts(entry);
                let resp_leaf = Self::response_leaf(tag, payload);
                let att_leaf = Self::att_leaf(self.attestation_at(i));
                poseidon2_hash(&[resp_leaf, att_leaf])
            })
            .collect();
        field_to_be_bytes32(poseidon2_hash(&leaves))
    }

    /// The attestation blob for entry `i` (empty slice when none).
    fn attestation_at(&self, i: usize) -> &[u8] {
        self.attestations
            .get(i)
            .map(|a| a.as_slice())
            .unwrap_or(&[])
    }

    /// Attestation leaf for one blob: `Poseidon2(att_len, att_bytes...)`.
    #[cfg(feature = "poseidon")]
    fn att_leaf(attestation: &[u8]) -> crate::host::poseidon2::FieldElement {
        let mut inputs = Vec::with_capacity(1 + attestation.len());
        inputs.push(u32_to_field(attestation.len() as u32));
        inputs.extend(bytes_to_fields(attestation));
        poseidon2_hash(&inputs)
    }

    /// Per-entry attestation leaves, serialized big-endian, in tape order.
    ///
    /// The Noir circuit takes these as witness and combines each with the
    /// response leaf it already computes — `Poseidon2(resp_leaf, att_leaf)` — to
    /// reproduce `attestation_commitment` *without* the raw attestation bytes
    /// in-circuit. Bind-only: the leaf is a pass-through commitment to the blob,
    /// which the circuit does not verify.
    #[cfg(feature = "poseidon")]
    pub fn attestation_leaves_be(&self) -> Vec<[u8; 32]> {
        self.entries
            .iter()
            .enumerate()
            .map(|(i, _)| field_to_be_bytes32(Self::att_leaf(self.attestation_at(i))))
            .collect()
    }

    // ── SHA-256 commitment scheme (zkVM backends) ────────────────────────────
    //
    // Structurally identical to the Poseidon2 scheme above, with SHA-256 as the
    // primitive and byte-string concatenation in place of field absorption.
    // Parity is deliberate: both backends must attest the same shape of claim,
    // so the only difference between them is the hash function.
    //
    // Poseidon2 is the right primitive inside a Noir/UltraHonk circuit, where
    // BN254 arithmetic is native and SHA-256 costs ~25k constraints per block.
    // In a RISC-V zkVM the cost model inverts: a Poseidon2 permutation is
    // software 254-bit modmul (488 field muls) absorbing only 3 bytes, while
    // SHA-256 is a single accelerated instruction per 64-byte block. Hence one
    // scheme per backend rather than one scheme everywhere.

    /// SHA-256 commitment over all tape entries in order.
    ///
    /// The zkVM-backend counterpart to [`OracleTape::commitment_hash`]:
    ///
    /// ```text
    ///     leaf_i      = SHA256( tag ‖ len_be32 ‖ payload )
    ///     commitment  = SHA256( n_be32 ‖ leaf_0 ‖ … ‖ leaf_{n-1} )
    /// ```
    ///
    /// The outer leaf count is prefixed for the same reason the Poseidon2
    /// sponge seeds its capacity with the message length: without it, tapes of
    /// different lengths could collide under concatenation.
    pub fn commitment_hash_sha256(&self) -> [u8; 32] {
        let mut outer = Sha256::new();
        outer.update((self.entries.len() as u32).to_be_bytes());
        for entry in &self.entries {
            let (tag, payload) = Self::entry_parts(entry);
            outer.update(Self::response_leaf_sha256(tag, payload));
        }
        outer.finalize().into()
    }

    /// Hex-encoded SHA-256 commitment hash (64 lowercase hex chars).
    pub fn commitment_hash_sha256_hex(&self) -> String {
        self.commitment_hash_sha256()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Bind-only provenance commitment under SHA-256.
    ///
    /// The zkVM-backend counterpart to [`OracleTape::attestation_commitment`],
    /// with the same nesting so each response leaf is shared between the two
    /// commitments:
    ///
    /// ```text
    ///     resp_leaf_i  = SHA256( tag ‖ resp_len_be32 ‖ resp_bytes )
    ///     att_leaf_i   = SHA256( att_len_be32 ‖ att_bytes )
    ///     bound_leaf_i = SHA256( resp_leaf_i ‖ att_leaf_i )
    ///     commitment   = SHA256( n_be32 ‖ bound_leaf_0 ‖ … )
    /// ```
    ///
    /// Bind, not verify: the attestation bytes are committed, never checked.
    pub fn attestation_commitment_sha256(&self) -> [u8; 32] {
        let mut outer = Sha256::new();
        outer.update((self.entries.len() as u32).to_be_bytes());
        for (i, entry) in self.entries.iter().enumerate() {
            let (tag, payload) = Self::entry_parts(entry);
            let mut bound = Sha256::new();
            bound.update(Self::response_leaf_sha256(tag, payload));
            bound.update(Self::att_leaf_sha256(self.attestation_at(i)));
            let bound: [u8; 32] = bound.finalize().into();
            outer.update(bound);
        }
        outer.finalize().into()
    }

    /// Per-entry attestation leaves under SHA-256, in tape order.
    ///
    /// The zkVM counterpart to [`OracleTape::attestation_leaves_be`]: a guest
    /// takes these as input and recombines them with the response leaves it
    /// computes, reproducing `attestation_commitment_sha256` without needing
    /// the raw attestation bytes.
    pub fn attestation_leaves_sha256(&self) -> Vec<[u8; 32]> {
        (0..self.entries.len())
            .map(|i| Self::att_leaf_sha256(self.attestation_at(i)))
            .collect()
    }

    /// `(tag, payload)` for one entry — `0x00` = Ok, `0x01` = Err.
    ///
    /// Shared by both commitment schemes so the tag/payload split cannot drift
    /// between them.
    fn entry_parts(entry: &TapeEntry) -> (u8, &[u8]) {
        match entry {
            TapeEntry::Ok(bytes) => (0x00, bytes.as_slice()),
            TapeEntry::Err(msg) => (0x01, msg.as_bytes()),
        }
    }

    /// Per-entry response leaf — `SHA256(tag ‖ len_be32 ‖ payload)`.
    fn response_leaf_sha256(tag: u8, payload: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([tag]);
        h.update((payload.len() as u32).to_be_bytes());
        h.update(payload);
        h.finalize().into()
    }

    /// Attestation leaf for one blob — `SHA256(att_len_be32 ‖ att_bytes)`.
    fn att_leaf_sha256(attestation: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update((attestation.len() as u32).to_be_bytes());
        h.update(attestation);
        h.finalize().into()
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
        ok_record_att(seq, response_json, &[])
    }

    fn ok_record_att(seq: usize, response_json: &[u8], attestation: &[u8]) -> ToolCallRecord {
        ToolCallRecord {
            seq,
            tool_name: "tool".to_owned(),
            args_canonical: b"{}".to_vec(),
            args_bytes: 2,
            response_hash: "".to_owned(),
            response_bytes: response_json.len(),
            response_canonical: response_json.to_vec(),
            error_message: String::new(),
            attestation: attestation.to_vec(),
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
            attestation: Vec::new(),
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

    #[cfg(feature = "poseidon")]
    #[test]
    fn commitment_hash_is_32_bytes() {
        let tape = OracleTape::from_records(&[ok_record(0, b"{}")]);
        let h = tape.commitment_hash();
        assert_eq!(h.len(), 32);
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn commitment_hash_hex_is_64_hex_chars() {
        let tape = OracleTape::from_records(&[ok_record(0, b"{}")]);
        let h = tape.commitment_hash_hex();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn commitment_hash_empty_tape_is_deterministic() {
        let h1 = OracleTape::new().commitment_hash();
        let h2 = OracleTape::new().commitment_hash();
        assert_eq!(h1, h2);
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn commitment_hash_differs_for_different_entries() {
        let t1 = OracleTape::from_records(&[ok_record(0, b"{\"a\":1}")]);
        let t2 = OracleTape::from_records(&[ok_record(0, b"{\"a\":2}")]);
        assert_ne!(t1.commitment_hash(), t2.commitment_hash());
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn commitment_hash_ok_vs_err_differs() {
        let t_ok = OracleTape::from_records(&[ok_record(0, b"\"msg\"")]);
        let t_err = OracleTape::from_records(&[err_record(0, "msg")]);
        assert_ne!(t_ok.commitment_hash(), t_err.commitment_hash());
    }

    // ── OracleTape::attestation_commitment (bind-only provenance) ─────────────

    #[cfg(feature = "poseidon")]
    #[test]
    fn attestation_commitment_is_32_bytes() {
        let tape = OracleTape::from_records(&[ok_record_att(0, b"{}", b"sig")]);
        assert_eq!(tape.attestation_commitment().len(), 32);
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn attestation_commitment_empty_tape_is_deterministic() {
        let h1 = OracleTape::new().attestation_commitment();
        let h2 = OracleTape::new().attestation_commitment();
        assert_eq!(h1, h2);
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn attestation_commitment_is_deterministic_for_same_tape() {
        // Replaying the same (response, attestation) pairs yields the identical
        // commitment — the determinism invariant the bind relies on.
        let recs = || vec![ok_record_att(0, b"{\"p\":1}", b"sigA"), err_record(1, "x")];
        let h1 = OracleTape::from_records(&recs()).attestation_commitment();
        let h2 = OracleTape::from_records(&recs()).attestation_commitment();
        assert_eq!(h1, h2);
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn attestation_commitment_binds_to_response_bytes() {
        // Same attestation, tampered response → different commitment.
        // This is the anti-"attestation-laundering" guarantee: an attestation
        // cannot be re-presented over response bytes it does not cover.
        let same_sig = b"sig";
        let t1 = OracleTape::from_records(&[ok_record_att(0, b"{\"price\":100}", same_sig)]);
        let t2 = OracleTape::from_records(&[ok_record_att(0, b"{\"price\":999}", same_sig)]);
        assert_ne!(t1.attestation_commitment(), t2.attestation_commitment());
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn attestation_commitment_binds_to_attestation_bytes() {
        // Same response, different attestation → different commitment.
        let resp = b"{\"price\":100}";
        let t1 = OracleTape::from_records(&[ok_record_att(0, resp, b"sigA")]);
        let t2 = OracleTape::from_records(&[ok_record_att(0, resp, b"sigB")]);
        assert_ne!(t1.attestation_commitment(), t2.attestation_commitment());
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn attestation_commitment_attested_differs_from_unattested() {
        let resp = b"{\"price\":100}";
        let attested = OracleTape::from_records(&[ok_record_att(0, resp, b"sig")]);
        let unattested = OracleTape::from_records(&[ok_record(0, resp)]);
        assert_ne!(
            attested.attestation_commitment(),
            unattested.attestation_commitment()
        );
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn attestation_commitment_is_independent_of_tool_responses_hash() {
        // The provenance commitment is a separate slot — it must not perturb the
        // existing tool_responses_hash, which the circuit recomputes.
        let attested = OracleTape::from_records(&[ok_record_att(0, b"{}", b"sig")]);
        let unattested = OracleTape::from_records(&[ok_record(0, b"{}")]);
        assert_eq!(attested.commitment_hash(), unattested.commitment_hash());
    }

    // ── SHA-256 commitment scheme (zkVM backends) ────────────────────────────

    /// Golden vectors computed independently of this implementation, so the
    /// test pins the wire format rather than snapshotting whatever the code
    /// happens to do. Preimages:
    ///     leaf       = SHA256( 0x00 ‖ 0x00000002 ‖ "{}" )
    ///     commitment = SHA256( 0x00000001 ‖ leaf )
    #[test]
    fn commitment_hash_sha256_matches_golden_vector() {
        let tape = OracleTape::from_records(&[ok_record(0, b"{}")]);
        assert_eq!(
            tape.commitment_hash_sha256_hex(),
            "ade1fdb799ff7c13ad62e1060eea55b72f53a9f012491f2e3bd989e801bb4ca4"
        );
    }

    /// `att_leaf = SHA256(0x00000000)` for the unattested entry, then
    /// `commitment = SHA256( 0x00000001 ‖ SHA256(resp_leaf ‖ att_leaf) )`.
    #[test]
    fn attestation_commitment_sha256_matches_golden_vector() {
        let tape = OracleTape::from_records(&[ok_record(0, b"{}")]);
        let hex: String = tape
            .attestation_commitment_sha256()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "0abdf04117475e4d4dec1286cb50c28d0a08e598ac5515dd8128cea354b8aba3"
        );
    }

    /// The empty tape commits to `SHA256(0x00000000)`, not `[0u8; 32]` — the
    /// same "absence is a real commitment" property the Poseidon2 scheme has.
    #[test]
    fn commitment_hash_sha256_empty_tape_is_length_prefix_only() {
        assert_eq!(
            OracleTape::new().commitment_hash_sha256_hex(),
            "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
        );
        assert_ne!(OracleTape::new().commitment_hash_sha256(), [0u8; 32]);
    }

    #[test]
    fn commitment_hash_sha256_hex_is_64_hex_chars() {
        let tape = OracleTape::from_records(&[ok_record(0, b"{}")]);
        let h = tape.commitment_hash_sha256_hex();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn commitment_hash_sha256_differs_for_different_entries() {
        let t1 = OracleTape::from_records(&[ok_record(0, b"{\"a\":1}")]);
        let t2 = OracleTape::from_records(&[ok_record(0, b"{\"a\":2}")]);
        assert_ne!(t1.commitment_hash_sha256(), t2.commitment_hash_sha256());
    }

    #[test]
    fn commitment_hash_sha256_ok_vs_err_differs() {
        // The 0x00/0x01 tag is what separates these two: both carry the same
        // payload bytes.
        let t_ok = OracleTape::from_records(&[ok_record(0, b"msg")]);
        let t_err = OracleTape::from_records(&[err_record(0, "msg")]);
        assert_ne!(
            t_ok.commitment_hash_sha256(),
            t_err.commitment_hash_sha256()
        );
    }

    /// Without the per-leaf length prefix, `["ab", "c"]` and `["a", "bc"]`
    /// would hash identically. This pins that the framing is unambiguous.
    #[test]
    fn commitment_hash_sha256_resists_payload_boundary_collisions() {
        let t1 = OracleTape::from_records(&[ok_record(0, b"ab"), ok_record(1, b"c")]);
        let t2 = OracleTape::from_records(&[ok_record(0, b"a"), ok_record(1, b"bc")]);
        assert_ne!(t1.commitment_hash_sha256(), t2.commitment_hash_sha256());
    }

    /// Same leaves, different tape length, must not collide — this is what the
    /// outer count prefix buys.
    #[test]
    fn commitment_hash_sha256_binds_entry_count() {
        let one = OracleTape::from_records(&[ok_record(0, b"{}")]);
        let two = OracleTape::from_records(&[ok_record(0, b"{}"), ok_record(1, b"{}")]);
        assert_ne!(one.commitment_hash_sha256(), two.commitment_hash_sha256());
    }

    #[test]
    fn commitment_hash_sha256_is_deterministic_across_rebuilds() {
        let recs = || vec![ok_record_att(0, b"{\"p\":1}", b"sigA"), err_record(1, "x")];
        let h1 = OracleTape::from_records(&recs()).commitment_hash_sha256();
        let h2 = OracleTape::from_records(&recs()).commitment_hash_sha256();
        assert_eq!(h1, h2);
    }

    #[test]
    fn attestation_commitment_sha256_binds_to_response_bytes() {
        let same_sig = b"sig";
        let t1 = OracleTape::from_records(&[ok_record_att(0, b"{\"price\":100}", same_sig)]);
        let t2 = OracleTape::from_records(&[ok_record_att(0, b"{\"price\":999}", same_sig)]);
        assert_ne!(
            t1.attestation_commitment_sha256(),
            t2.attestation_commitment_sha256()
        );
    }

    #[test]
    fn attestation_commitment_sha256_binds_to_attestation_bytes() {
        let resp = b"{\"price\":100}";
        let t1 = OracleTape::from_records(&[ok_record_att(0, resp, b"sigA")]);
        let t2 = OracleTape::from_records(&[ok_record_att(0, resp, b"sigB")]);
        assert_ne!(
            t1.attestation_commitment_sha256(),
            t2.attestation_commitment_sha256()
        );
    }

    #[test]
    fn attestation_commitment_sha256_is_independent_of_tool_responses_hash() {
        let attested = OracleTape::from_records(&[ok_record_att(0, b"{}", b"sig")]);
        let unattested = OracleTape::from_records(&[ok_record(0, b"{}")]);
        assert_eq!(
            attested.commitment_hash_sha256(),
            unattested.commitment_hash_sha256()
        );
        assert_ne!(
            attested.attestation_commitment_sha256(),
            unattested.attestation_commitment_sha256()
        );
    }

    /// A guest recombines these leaves with the response leaves it computes, so
    /// the count must line up with the tape and the values must be stable.
    #[test]
    fn attestation_leaves_sha256_align_with_entries() {
        let tape =
            OracleTape::from_records(&[ok_record_att(0, b"{}", b"sigA"), ok_record(1, b"{}")]);
        let leaves = tape.attestation_leaves_sha256();
        assert_eq!(leaves.len(), 2);
        assert_ne!(leaves[0], leaves[1]);
        assert_eq!(leaves, tape.attestation_leaves_sha256());
    }

    /// The two schemes commit the same claim with different primitives; they
    /// must not be confused for one another at a call site.
    #[cfg(feature = "poseidon")]
    #[test]
    fn sha256_and_poseidon_commitments_are_distinct() {
        let tape = OracleTape::from_records(&[ok_record(0, b"{}")]);
        assert_ne!(tape.commitment_hash(), tape.commitment_hash_sha256());
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
