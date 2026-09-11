//! OpenVM guest smoke test.
//!
//! This is not the real replay guest yet — it does not execute bytecode or
//! consume an oracle tape. Its job is narrower: prove that the `proveno` core
//! crate builds *and runs* on a RISC-V zkVM target under
//! `--no-default-features --features zkvm`, and that the SHA-256 commitment
//! scheme it grew for zkVM backends produces values inside the guest.
//!
//! The Poseidon2 scheme cannot be used here. It is not a size or taste
//! judgement: `bn254_blackbox_solver` pulls wasmer -> cranelift ->
//! target-lexicon 0.12, whose build script hard-panics on the custom RISC-V
//! target triple, and cargo runs that build script whether or not the code is
//! ever linked. Beyond the build failure, a Poseidon2 permutation in RISC-V is
//! 488 software 254-bit modmuls absorbing 3 bytes, against one accelerated
//! instruction per 64-byte block for SHA-256.

use openvm::io::{read, reveal_u32};
use openvm_sha2::Sha256;
// On zkvm targets `Sha256`'s new/update/finalize are inherent; on host targets
// they come from the `sha2` Digest trait, which must then be in scope.
#[cfg(not(target_os = "zkvm"))]
use openvm_sha2::Digest;
use proveno::host::tape::{OracleTape, TapeEntry};

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

/// Fibonacci, then both hash paths: accelerated SHA-256 over the result, then
/// proveno's guest-side tape commitment over that digest.
///
/// Split out of `main` so the host build can pin it with a golden vector; the
/// guest and host must agree byte-for-byte or a replay proof means nothing.
fn commit_fib(n: u64) -> [u8; 32] {
    let mut a: u64 = 0;
    let mut b: u64 = 1;
    for _ in 0..n {
        let c: u64 = a.wrapping_add(b);
        a = b;
        b = c;
    }

    // Hash the result through OpenVM's accelerated SHA-256 chip.
    //
    // `openvm_sha2::Sha256` has the same streaming new/update/finalize shape as
    // `sha2::Sha256` (on host targets it *is* `sha2::Sha256`, re-exported), so
    // proveno's commitment code could route through the accelerator behind a
    // type alias rather than being rewritten. That is not wired up yet, so the
    // tape commitment below still runs software SHA-256 inside the guest —
    // far cheaper than Poseidon2 would be, but leaving the chip idle.
    let mut h = Sha256::new();
    // The borrow is required on zkvm targets, where `update` takes `&[u8]`
    // rather than the host `Digest::update`'s `impl AsRef<[u8]>`. clippy only
    // ever sees the host signature, so its suggestion would break the guest.
    #[allow(clippy::needless_borrows_for_generic_args)]
    h.update(&a.to_be_bytes());
    let accelerated: [u8; 32] = h.finalize().into();

    // Feed that digest through proveno's guest-side commitment scheme, so the
    // core crate is genuinely exercised rather than merely linked.
    let tape = OracleTape {
        entries: vec![TapeEntry::Ok(accelerated.to_vec())],
        attestations: vec![Vec::new()],
    };
    tape.commitment_hash_sha256()
}

fn main() {
    let n: u64 = read();
    // Exactly 8 words, which is the default public-values budget.
    reveal_digest(commit_fib(n), 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector computed independently of this code, and confirmed to
    /// match what the guest reveals under
    /// `cargo openvm run -p proveno-openvm --input 0x010a00000000000000`:
    ///
    /// ```text
    /// fib(10)     = 55
    /// accelerated = SHA256( 55u64.to_be_bytes() )
    /// leaf        = SHA256( 0x00 ‖ 0x00000020 ‖ accelerated )
    /// commitment  = SHA256( 0x00000001 ‖ leaf )
    /// ```
    #[test]
    fn commit_fib_matches_guest_execution() {
        let hex: String = commit_fib(10).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "c23646299c0795de5e76f00cf97f5c406c8b977cc1ff583b4b4d17d63a1866da"
        );
    }

    #[test]
    fn commit_fib_is_deterministic() {
        assert_eq!(commit_fib(10), commit_fib(10));
        assert_ne!(commit_fib(10), commit_fib(11));
    }
}
