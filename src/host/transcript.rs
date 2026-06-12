//! Tool call transcript — typed records of every tool call made during execution.

#[cfg(not(feature = "std"))]
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec::Vec,
};
use sha2::{Digest, Sha256};

/// Status of a tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ToolCallStatus {
    Ok,
    Error,
}

/// A single recorded tool call.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ToolCallRecord {
    /// 0-indexed sequence number.
    pub seq: usize,
    /// The tool name string.
    pub tool_name: String,
    /// Canonical JSON bytes of the serialized arguments.
    pub args_canonical: Vec<u8>,
    /// Byte length of `args_canonical`.
    pub args_bytes: usize,
    /// SHA-256 hex string of the canonical response bytes (empty string on error).
    pub response_hash: String,
    /// Byte length of the canonical response bytes (0 on error).
    pub response_bytes: usize,
    /// Canonical JSON bytes of the response table (empty on error).
    /// Used to construct an `OracleTape` for zkVM replay.
    pub response_canonical: Vec<u8>,
    /// Error message returned by the host (empty string on success).
    /// Used to replay `Err(msg)` responses from an `OracleTape`.
    pub error_message: String,
    /// Provenance attestation blob the host sourced for this response (empty
    /// when none). Bind-only: committed alongside the response bytes, not
    /// verified here. Always empty for failed calls.
    #[cfg_attr(feature = "serde", serde(default))]
    pub attestation: Vec<u8>,
    /// Gas charged for this tool call (0 for failed calls).
    pub gas_charged: u64,
    /// Status of the call.
    pub status: ToolCallStatus,
}

/// Accumulates tool call records for the current execution.
#[derive(Debug, Default)]
pub struct Transcript {
    records: Vec<ToolCallRecord>,
}

impl Transcript {
    pub fn new() -> Self {
        Transcript {
            records: Vec::new(),
        }
    }

    /// Record a successful tool call with no provenance attestation.
    pub fn record_ok(
        &mut self,
        tool_name: &str,
        args_canonical: Vec<u8>,
        response_canonical: Vec<u8>,
        gas_charged: u64,
    ) {
        self.record_ok_attested(
            tool_name,
            args_canonical,
            response_canonical,
            Vec::new(),
            gas_charged,
        );
    }

    /// Record a successful tool call along with the provenance attestation the
    /// host sourced for it (empty `attestation` is equivalent to `record_ok`).
    pub fn record_ok_attested(
        &mut self,
        tool_name: &str,
        args_canonical: Vec<u8>,
        response_canonical: Vec<u8>,
        attestation: Vec<u8>,
        gas_charged: u64,
    ) {
        let seq = self.records.len();
        let args_bytes = args_canonical.len();
        let response_bytes = response_canonical.len();
        let response_hash = sha256_hex(&response_canonical);

        self.records.push(ToolCallRecord {
            seq,
            tool_name: tool_name.to_owned(),
            args_canonical,
            args_bytes,
            response_hash,
            response_bytes,
            response_canonical,
            error_message: String::new(),
            attestation,
            gas_charged,
            status: ToolCallStatus::Ok,
        });
    }

    /// Record a failed tool call.
    pub fn record_error(
        &mut self,
        tool_name: &str,
        args_canonical: Vec<u8>,
        gas_charged: u64,
        error_message: &str,
    ) {
        let seq = self.records.len();
        let args_bytes = args_canonical.len();

        self.records.push(ToolCallRecord {
            seq,
            tool_name: tool_name.to_owned(),
            args_canonical,
            args_bytes,
            response_hash: String::new(),
            response_bytes: 0,
            response_canonical: Vec::new(),
            error_message: error_message.to_owned(),
            attestation: Vec::new(),
            gas_charged,
            status: ToolCallStatus::Error,
        });
    }

    pub fn records(&self) -> &[ToolCallRecord] {
        &self.records
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let hash_bytes = Sha256::digest(data);
    hash_bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_transcript() {
        let t = Transcript::new();
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
        assert_eq!(t.records().len(), 0);
    }

    #[test]
    fn record_ok_basic() {
        let mut t = Transcript::new();
        t.record_ok(
            "search",
            b"{\"query\":\"x\"}".to_vec(),
            b"{\"result\":1}".to_vec(),
            200,
        );
        assert_eq!(t.len(), 1);
        let r = &t.records()[0];
        assert_eq!(r.seq, 0);
        assert_eq!(r.tool_name, "search");
        assert_eq!(r.args_canonical, b"{\"query\":\"x\"}");
        assert_eq!(r.args_bytes, 13);
        assert_eq!(r.response_bytes, 12);
        assert_eq!(r.gas_charged, 200);
        assert_eq!(r.status, ToolCallStatus::Ok);
        // response_hash should be a 64-char hex string
        assert_eq!(r.response_hash.len(), 64);
        assert!(r.response_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn record_ok_correct_sha256() {
        let mut t = Transcript::new();
        let response = b"hello";
        t.record_ok("tool", vec![], response.to_vec(), 0);

        // Known SHA-256 of "hello"
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(t.records()[0].response_hash, expected);
    }

    #[test]
    fn seq_increments() {
        let mut t = Transcript::new();
        t.record_ok("a", vec![], vec![], 0);
        t.record_ok("b", vec![], vec![], 0);
        t.record_error("c", vec![], 0, "err c");
        assert_eq!(t.records()[0].seq, 0);
        assert_eq!(t.records()[1].seq, 1);
        assert_eq!(t.records()[2].seq, 2);
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn record_error_status() {
        let mut t = Transcript::new();
        t.record_error("fail_tool", b"{}".to_vec(), 0, "something failed");
        let r = &t.records()[0];
        assert_eq!(r.status, ToolCallStatus::Error);
        assert_eq!(r.tool_name, "fail_tool");
        assert_eq!(r.response_hash, "");
        assert_eq!(r.response_bytes, 0);
        assert_eq!(r.gas_charged, 0);
    }

    #[test]
    fn record_ok_has_empty_attestation_by_default() {
        let mut t = Transcript::new();
        t.record_ok("tool", vec![], b"resp".to_vec(), 0);
        assert!(t.records()[0].attestation.is_empty());
    }

    #[test]
    fn record_ok_attested_stores_blob() {
        let mut t = Transcript::new();
        t.record_ok_attested("tool", vec![], b"resp".to_vec(), b"sig".to_vec(), 0);
        assert_eq!(t.records()[0].attestation, b"sig");
        // Attestation does not perturb the response hash.
        let mut t2 = Transcript::new();
        t2.record_ok("tool", vec![], b"resp".to_vec(), 0);
        assert_eq!(t.records()[0].response_hash, t2.records()[0].response_hash);
    }

    #[test]
    fn record_error_has_empty_attestation() {
        let mut t = Transcript::new();
        t.record_error("broken", vec![], 0, "boom");
        assert!(t.records()[0].attestation.is_empty());
    }

    #[test]
    fn record_error_after_ok() {
        let mut t = Transcript::new();
        t.record_ok("first", vec![], b"resp".to_vec(), 100);
        t.record_error("second", vec![], 0, "second failed");
        assert_eq!(t.len(), 2);
        assert_eq!(t.records()[0].status, ToolCallStatus::Ok);
        assert_eq!(t.records()[1].status, ToolCallStatus::Error);
        assert_eq!(t.records()[1].seq, 1);
    }
}
