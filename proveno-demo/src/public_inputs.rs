//! Owned `PublicInputs` for the on-chain `ProvenoVerifier.verify` call.
//!
//! Distinct from `proveno::zkvm::commitment::PublicInputs`: this carries the
//! `num_steps` (u32) and `return_value` (i64) scalars too, since those are
//! part of the contract tuple but aren't part of the commitment struct.

/// The 8-field tuple consumed by `ProvenoVerifier.verify`. Field order matches
/// `contracts/src/Types.sol::PublicInputs` exactly.
#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub num_steps: u32,
    pub program_hash: [u8; 32],
    pub return_value: i64,
    pub tool_responses_hash: [u8; 32],
    pub input_hash: [u8; 32],
    pub output_hash: [u8; 32],
    pub attestation_hash: [u8; 32],
    pub policy_hash: [u8; 32],
}
