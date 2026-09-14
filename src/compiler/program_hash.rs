//! The canonical definition of a program hash.
//!
//! Two schemes, both keyed off the same instruction stream the VM executes:
//!
//! | Scheme | Feature | Consumer |
//! |---|---|---|
//! | Poseidon2 | `poseidon` | the Noir circuit, where BN254 is native |
//! | SHA-256 | always | zkVM backends, where SHA-256 is an accelerated instruction |
//!
//! `program_hash` is backend-specific. A verifier must recompute it with the
//! same scheme the prover used.
//!
//! This lives next to the compiler that produces the prototypes rather than
//! next to a prover: `codegen` calls it on every compile, so putting it in a
//! backend module made the compiler depend on that backend.

#[cfg(feature = "poseidon")]
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::{
    compiler::proto::FunctionProto,
    isa::opcodes::{instruction_to_opcode_id, instruction_to_operand},
};

#[cfg(feature = "poseidon")]
use crate::host::poseidon2::{field_to_be_bytes32, i64_to_field, poseidon2_hash, u8_to_field};

/// Compute the Poseidon2 program hash over a flat sequence of (opcode, operand)
/// pairs. This is the single source of truth for "the program hash" in the
/// Rust tree, and it matches `assert_bytecode` in noir/src/main.nr byte-for-byte:
///
/// ```text
/// hash_input[i*2]     = opcodes[i]  as Field   // u8  → Field
/// hash_input[i*2 + 1] = operands[i] as u64 as Field  // i64 → u64 bit-pattern → Field
/// program_hash        = Poseidon2::hash(hash_input, instr_count * 2)
/// ```
///
/// Callers feed it the same instruction stream the witness writer packs into
/// `bytecode_opcodes` / `bytecode_operands` (the encoder builds that stream
/// from `program.prototypes` in declaration order).
#[cfg(feature = "poseidon")]
pub fn compute_program_hash(prototypes: &[FunctionProto]) -> [u8; 32] {
    let count: usize = prototypes.iter().map(|p| p.code.len()).sum();
    let mut inputs = Vec::with_capacity(count * 2);
    for proto in prototypes {
        for instr in &proto.code {
            inputs.push(u8_to_field(instruction_to_opcode_id(instr)));
            inputs.push(i64_to_field(instruction_to_operand(instr)));
        }
    }
    field_to_be_bytes32(poseidon2_hash(&inputs))
}

/// Compute the SHA-256 program hash, for zkVM proving backends.
///
/// Unlike [`compute_program_hash`], this covers the **whole program**, not just
/// the `(opcode, operand)` instruction stream:
///
/// ```text
/// preimage = proto_count_be32
///            ‖ for each prototype:
///                param_count_u8 ‖ local_count_u8 ‖ upvalue_count_u8
///                ‖ upvalue_count_be32 ‖ ( kind_u8 ‖ index_u8 ) *
///                ‖ constant_count_be32 ‖ ( tag_u8 ‖ payload ) *
///                ‖ instr_count_be32   ‖ ( opcode_u8 ‖ operand_u64_be ) *
/// ```
///
/// Hashing the instruction stream alone is **not** sufficient to identify a
/// program. `PushK(i)`, `GetField(i)` and `SetField(i)` carry a constant-pool
/// *index* as their operand, so `return 1`, `return 2` and `return "omega"` all
/// compile to the identical `PushK(0); Ret(1)` stream. A hash over that stream
/// cannot tell them apart, which would let a prover swap the constant pool —
/// every literal in the program — while still matching the committed hash.
///
/// Every element is length-prefixed or fixed-width so no two distinct programs
/// can share a preimage. `lines` and `max_stack` are deliberately excluded:
/// the former is source-position debug data with no effect on execution, and
/// the latter is derived from the code and re-checked by the bytecode verifier.
///
/// Operands are widened through their `u64` bit pattern exactly as
/// `i64_to_field` does on the Poseidon2 path, so `-1i64` encodes as
/// `0xffff_ffff_ffff_ffff` under both.
///
/// `program_hash` is backend-specific, like `tool_responses_hash` and
/// `attestation_hash`: a verifier must recompute it with the same scheme the
/// prover used. See [`CompiledProgram::program_hash`] for which scheme a given
/// build produces.
pub fn compute_program_hash_sha256(prototypes: &[FunctionProto]) -> [u8; 32] {
    use crate::compiler::proto::{Constant, UpvalueDesc};

    let mut h = Sha256::new();
    h.update((prototypes.len() as u32).to_be_bytes());

    for proto in prototypes {
        h.update([proto.param_count, proto.local_count, proto.upvalue_count]);

        h.update((proto.upvalues.len() as u32).to_be_bytes());
        for up in &proto.upvalues {
            match up {
                UpvalueDesc::Local(i) => h.update([0x00, *i]),
                UpvalueDesc::Upvalue(i) => h.update([0x01, *i]),
            }
        }

        h.update((proto.constants.len() as u32).to_be_bytes());
        for k in &proto.constants {
            match k {
                Constant::Nil => h.update([0x00]),
                Constant::Boolean(b) => h.update([0x01, u8::from(*b)]),
                Constant::Integer(n) => {
                    h.update([0x02]);
                    h.update((*n as u64).to_be_bytes());
                }
                Constant::String(bytes) => {
                    h.update([0x03]);
                    h.update((bytes.len() as u32).to_be_bytes());
                    h.update(bytes);
                }
                Constant::Proto(idx) => {
                    h.update([0x04]);
                    h.update(idx.to_be_bytes());
                }
            }
        }

        h.update((proto.code.len() as u32).to_be_bytes());
        for instr in &proto.code {
            h.update([instruction_to_opcode_id(instr)]);
            h.update((instruction_to_operand(instr) as u64).to_be_bytes());
        }
    }

    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compiler::compile, compiler::proto::CompiledProgram, parser::parse};
    use alloc::{format, string::String};

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn compile_lua(src: &str) -> CompiledProgram {
        let block = parse(src).expect("parse");
        compile(&block).expect("compile")
    }

    #[test]
    fn sha256_hash_distinguishes_integer_constants() {
        let a = compile_lua("return 1");
        let b = compile_lua("return 2");
        let c = compile_lua("return 999999");
        let ha = compute_program_hash_sha256(&a.prototypes);
        let hb = compute_program_hash_sha256(&b.prototypes);
        let hc = compute_program_hash_sha256(&c.prototypes);
        assert_ne!(ha, hb);
        assert_ne!(hb, hc);
        assert_ne!(ha, hc);
    }

    #[test]
    fn sha256_hash_distinguishes_string_constants() {
        let a = compute_program_hash_sha256(&compile_lua("return \"alpha\"").prototypes);
        let b = compute_program_hash_sha256(&compile_lua("return \"omega\"").prototypes);
        assert_ne!(a, b);
    }

    /// `GetField(i)` also indexes the constant pool, so the field *name* must
    /// reach the hash too.
    #[test]
    fn sha256_hash_distinguishes_field_names() {
        let a = compute_program_hash_sha256(&compile_lua("local t = {} return t.alpha").prototypes);
        let b = compute_program_hash_sha256(&compile_lua("local t = {} return t.omega").prototypes);
        assert_ne!(a, b);
    }

    /// Length prefixes must make the string pool unambiguous: `["ab", "c"]` and
    /// `["a", "bc"]` would otherwise share a preimage.
    #[test]
    fn sha256_hash_resists_constant_boundary_collisions() {
        let a = compute_program_hash_sha256(
            &compile_lua("local x = \"ab\" local y = \"c\" return x .. y").prototypes,
        );
        let b = compute_program_hash_sha256(
            &compile_lua("local x = \"a\" local y = \"bc\" return x .. y").prototypes,
        );
        assert_ne!(a, b);
    }

    /// Upvalue descriptors must reach the hash. These two programs compile to
    /// byte-identical instruction streams *and* identical constant pools — the
    /// only difference anywhere is prototype 1's `upvalues`, which is
    /// `[Local(0)]` in one and `[Local(1)]` in the other. A hash that skipped
    /// the descriptors would let a prover repoint a closure at a different
    /// captured local (here: return 20 instead of 10) under the committed
    /// program hash.
    #[test]
    fn sha256_hash_distinguishes_upvalue_descriptors() {
        let a = compile_lua("local a = 10 local b = 20 local function f() return a end return f()");
        let b = compile_lua("local a = 10 local b = 20 local function f() return b end return f()");

        // Pin the premise: nothing but the upvalue descriptor differs.
        assert_eq!(a.prototypes.len(), b.prototypes.len());
        for (pa, pb) in a.prototypes.iter().zip(&b.prototypes) {
            assert_eq!(pa.code, pb.code);
            assert_eq!(pa.constants, pb.constants);
        }
        assert_ne!(a.prototypes[1].upvalues, b.prototypes[1].upvalues);

        assert_ne!(
            compute_program_hash_sha256(&a.prototypes),
            compute_program_hash_sha256(&b.prototypes)
        );
    }

    /// Prototype metadata (`param_count` / `local_count` / `upvalue_count`)
    /// must reach the hash too: arity decides how the VM binds arguments to
    /// slots, and these two bodies compile to the same instructions.
    #[test]
    fn sha256_hash_distinguishes_prototype_arity() {
        let a = compile_lua("local function f(x) return 1 end return f(7)");
        let b = compile_lua("local function f(x, y) return 1 end return f(7)");
        assert_ne!(a.prototypes[1].param_count, b.prototypes[1].param_count);
        assert_ne!(
            compute_program_hash_sha256(&a.prototypes),
            compute_program_hash_sha256(&b.prototypes)
        );
    }

    #[test]
    fn sha256_hash_is_stable_across_compilations() {
        let a = compute_program_hash_sha256(&compile_lua("return 1 + 2").prototypes);
        let b = compute_program_hash_sha256(&compile_lua("return 1 + 2").prototypes);
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_hash_distinguishes_different_code() {
        let a = compute_program_hash_sha256(&compile_lua("return 1 + 2").prototypes);
        let b = compute_program_hash_sha256(&compile_lua("return 1 - 2").prototypes);
        assert_ne!(a, b);
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn poseidon_hash_is_stable_across_compilations() {
        let a = compile_lua("return 1 + 2");
        let b = compile_lua("return 1 + 2");
        assert_eq!(
            compute_program_hash(&a.prototypes),
            compute_program_hash(&b.prototypes)
        );
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn poseidon_hash_differs_for_different_code() {
        let a = compile_lua("return 1 + 2");
        let b = compile_lua("local x = 0; for i = 1, 10 do x = x + i end; return x");
        assert_ne!(
            compute_program_hash(&a.prototypes),
            compute_program_hash(&b.prototypes)
        );
    }

    /// Pins the hash a default-featured build produces for a fixed program.
    ///
    /// `codegen` selects the scheme on the `poseidon` feature, so a change to
    /// the default feature set silently changes every committed
    /// `program_hash` with no compile error and no other failing test. This
    /// fixture makes that change loud.
    #[cfg(feature = "poseidon")]
    #[test]
    fn poseidon_hash_matches_recorded_fixture() {
        let p = compile_lua("return 1 + 2");
        assert_eq!(
            hex(&compute_program_hash(&p.prototypes)),
            "229de77f7b7d28f3401e32e1ad6b80b444a2bc3305cba3744a7154944d3ce09e"
        );
    }

    /// The SHA-256 counterpart, which the zkVM backends commit to.
    #[test]
    fn sha256_hash_matches_recorded_fixture() {
        let p = compile_lua("return 1 + 2");
        assert_eq!(
            hex(&compute_program_hash_sha256(&p.prototypes)),
            "d21b0722b0249276e4159b38cb69bc09b73d2e4f32f0c176a2ec33d9b29d2cab"
        );
    }
}
