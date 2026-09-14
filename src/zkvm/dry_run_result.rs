//! `DryRunResult` — the bundle produced by a host-side dry-run.
//!
//! Carries everything downstream consumers (the OpenVM encoder, the on-chain
//! verifier, the test harness) need to feed a guest replay or check a proof:
//! the recorded VM output, the oracle tape, captured provenance attestations,
//! and the computed public inputs. The type is pure data so it can be
//! deserialized inside the zkVM guest without dragging in any host-only
//! dependencies.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::{host::tape::OracleTape, vm::engine::VmOutput, zkvm::commitment::PublicInputs};

/// Result of a dry run: the VM output, oracle tape, provenance attestations,
/// and the public inputs computed from all of the above.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DryRunResult {
    pub output: VmOutput,
    pub oracle_tape: OracleTape,
    /// Per-call provenance attestations, as opaque bytes.
    ///
    /// Deliberately untyped: a provider plugs in at
    /// `HostInterface::take_attestation`, which yields `Vec<u8>`, and this
    /// layer only carries the blobs. Typing them as TLS records would make
    /// the proving path depend on one specific provenance provider.
    ///
    /// Not hashed here. `attestation_hash` is derived from the oracle tape via
    /// `OracleTape::attestation_commitment`, which binds each blob to the
    /// response it covers. This field is the human-readable carry-through.
    ///
    /// Empty when no provider is attached.
    pub attestations: Vec<Vec<u8>>,
    pub public_inputs: PublicInputs,
}
