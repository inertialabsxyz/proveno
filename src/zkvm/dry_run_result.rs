//! `DryRunResult` — the bundle produced by a host-side dry-run.
//!
//! Carries everything downstream consumers (the OpenVM encoder, the on-chain
//! verifier, the test harness) need to feed a guest replay or check a proof:
//! the recorded VM output, the oracle tape, captured TLS attestations, and the
//! computed public inputs. The type is pure data so it can be deserialized
//! inside the zkVM guest without dragging in any host-only dependencies.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::{
    host::tape::OracleTape, tls::TlsAttestationRecord, vm::engine::VmOutput,
    zkvm::commitment::PublicInputs,
};

/// Result of a dry run: the VM output, oracle tape, TLS attestations, and
/// the public inputs computed from all of the above.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DryRunResult {
    pub output: VmOutput,
    pub oracle_tape: OracleTape,
    /// TLS attestation records captured during HTTP(S) tool calls.
    /// Empty when the host does not make HTTPS calls or does not support
    /// TLS attestation.
    pub tls_attestations: Vec<TlsAttestationRecord>,
    pub public_inputs: PublicInputs,
}
