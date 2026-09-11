//! OpenVM zkVM guest: proves that a compiled Lua program executed as written.
//!
//! Reads a [`GuestInput`] (bytecode, input value, oracle tape, VM config),
//! replays the program against a [`TapeHost`] so no external calls happen,
//! recomputes every commitment from what it actually executed, and reveals a
//! single digest over them.
//!
//! # Why SHA-256 and not Poseidon2
//!
//! The Noir backend commits with Poseidon2, which is right inside a circuit
//! where BN254 arithmetic is native. In a RISC-V zkVM the cost model inverts:
//! one Poseidon2 permutation is 488 software 254-bit modmuls that absorb only
//! 3 bytes, against one accelerated instruction per 64-byte block for SHA-256.
//! It is also a hard build constraint — `bn254_blackbox_solver` drags in
//! wasmer -> cranelift -> target-lexicon 0.12, whose build script panics on
//! this target triple. Hence `default-features = false` on the proveno dep.
//!
//! # What the proof binds
//!
//! See [`GuestInput::replay_public_inputs`], which is the whole of the proven
//! computation and is shared verbatim with the host driver.

use openvm::io::{read, reveal_u32};
use proveno::zkvm::guest_input::GuestInput;

/// Reveal a 32-byte digest as 8 `u32` public values starting at `slot`.
///
/// Packed little-endian: OpenVM lays each revealed word back out in that order,
/// so LE packing is what makes the public-value byte stream read back as the
/// digest itself rather than as each 4-byte group reversed.
fn reveal_digest(digest: [u8; 32], slot: usize) {
    for (i, word) in digest.as_chunks::<4>().0.iter().enumerate() {
        reveal_u32(u32::from_le_bytes(*word), slot + i);
    }
}

fn main() {
    let input: GuestInput = read();

    // The replay and every commitment live in `GuestInput::replay_public_inputs`
    // so the host driver can call the identical code and predict exactly what
    // this guest reveals. See that function for what the proof does and does
    // not bind.
    let (_output, public_inputs) = input
        .replay_public_inputs()
        .expect("guest replay diverged from the dry run");

    // One digest rather than all six commitments: 32 bytes is OpenVM's default
    // public-values budget, and each public value costs proving work. The
    // verifier receives the six values out of band and recomputes this.
    reveal_digest(public_inputs.digest_sha256(), 0);
}
