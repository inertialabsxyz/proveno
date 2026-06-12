//! Poseidon2 hashing matching `noir-lang/poseidon v0.3.0`'s
//! `Poseidon2::hash_internal` sponge framing.
//!
//! State width 4, rate 3, capacity 1. The capacity slot is initialised to
//! `(message_length as Field) * 2^64` (domain separator). Output is the first
//! state element after the final permutation.
//!
//! Input mode is byte-per-field — each input byte (or other small integer) is
//! converted to one BN254 field element. This matches the reference Rust code
//! used by the existing prover and the way the Noir circuit feeds bytes into
//! `Poseidon2::hash`.

pub(crate) use acir::FieldElement;
use bn254_blackbox_solver::poseidon2_permutation;

const RATE: usize = 3;
const STATE_WIDTH: u32 = 4;

/// Compute the Poseidon2 sponge hash of a field-element vector.
///
/// Mirrors `Poseidon2::hash_internal` from noir-lang/poseidon v0.3.0
/// (src/poseidon2.nr) so on-host and in-circuit hashes agree.
pub fn poseidon2_hash(inputs: &[FieldElement]) -> FieldElement {
    let in_len = inputs.len();
    let two_pow_64 = FieldElement::from(1u128 << 64);
    let iv = FieldElement::from(in_len as u128) * two_pow_64;

    let mut state = [FieldElement::zero(); 4];
    state[3] = iv;

    let full_chunks = in_len / RATE;
    for chunk_idx in 0..full_chunks {
        for i in 0..RATE {
            state[i] += inputs[chunk_idx * RATE + i];
        }
        let permuted = poseidon2_permutation(&state, STATE_WIDTH).expect("permutation");
        state.copy_from_slice(&permuted);
    }

    let remainder_start = full_chunks * RATE;
    for j in 0..RATE {
        let idx = remainder_start + j;
        if idx < in_len {
            state[j] += inputs[idx];
        }
    }

    if in_len == 0 || in_len % RATE != 0 {
        let permuted = poseidon2_permutation(&state, STATE_WIDTH).expect("permutation");
        state.copy_from_slice(&permuted);
    }

    state[0]
}

// ── Conversion helpers ───────────────────────────────────────────────────────

/// Field element → 32-byte big-endian array, the canonical encoding used to
/// shuttle Poseidon2 hashes through `[u8; 32]`-typed public-input fields.
pub fn field_to_be_bytes32(f: FieldElement) -> [u8; 32] {
    let bytes = f.to_be_bytes();
    debug_assert_eq!(
        bytes.len(),
        32,
        "FieldElement::to_be_bytes returned {} bytes",
        bytes.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Bytes → field elements, one byte per field. Matches the Noir-side input
/// convention where each `u8` is widened to a `Field`.
pub fn bytes_to_fields(bytes: &[u8]) -> Vec<FieldElement> {
    bytes
        .iter()
        .map(|b| FieldElement::from(u128::from(*b)))
        .collect()
}

/// `u32` → one field element, used for length prefixes.
pub fn u32_to_field(x: u32) -> FieldElement {
    FieldElement::from(u128::from(x))
}

/// `u8` → one field element, used for tag bytes.
pub fn u8_to_field(x: u8) -> FieldElement {
    FieldElement::from(u128::from(x))
}

/// `i64` → one field element by interpreting the bit pattern as `u64`.
/// `-1i64` becomes `u64::MAX` in the field; positive values are unchanged.
/// The Noir side performs the same widening when bytecode operands are loaded.
pub fn i64_to_field(x: i64) -> FieldElement {
    FieldElement::from(u128::from(x as u64))
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_hash_is_stable() {
        let h1 = poseidon2_hash(&[]);
        let h2 = poseidon2_hash(&[]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_produce_different_hashes() {
        let h1 = poseidon2_hash(&[FieldElement::from(1u128)]);
        let h2 = poseidon2_hash(&[FieldElement::from(2u128)]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn length_changes_hash_via_iv() {
        // Same first input, different total length → IV differs → hash differs.
        let h1 = poseidon2_hash(&[FieldElement::from(5u128)]);
        let h2 = poseidon2_hash(&[FieldElement::from(5u128), FieldElement::zero()]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn field_to_be_bytes32_is_32_bytes() {
        let f = FieldElement::from(0x123456789abcdef0u128);
        let bytes = field_to_be_bytes32(f);
        // Low 8 bytes carry the value, high 24 bytes are zero (BE encoding).
        assert_eq!(&bytes[0..24], &[0u8; 24]);
        assert_eq!(&bytes[24..], &0x123456789abcdef0u64.to_be_bytes());
    }

    #[test]
    fn bytes_to_fields_length_matches_input() {
        let bytes = b"hello";
        let fields = bytes_to_fields(bytes);
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0], FieldElement::from(b'h' as u128));
        assert_eq!(fields[4], FieldElement::from(b'o' as u128));
    }

    #[test]
    fn i64_to_field_handles_negative() {
        let neg = i64_to_field(-1);
        let max = FieldElement::from(u64::MAX as u128);
        assert_eq!(neg, max);
    }
}
