use crate::compiler::proto::CompiledProgram;
#[cfg(feature = "poseidon")]
use crate::host::poseidon2::{field_to_be_bytes32, i64_to_field, poseidon2_hash, u8_to_field};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use super::opcodes::{instruction_to_opcode_id, instruction_to_operand};

pub const MAX_BYTECODE: usize = 512;

pub struct NoirBytecode {
    pub opcodes: [u8; MAX_BYTECODE],
    pub operands: [i64; MAX_BYTECODE],
    pub program_hash: [u8; 32],
    pub instr_count: usize,
    /// Byte offset of each prototype in the flat bytecode array.
    /// `prototype_offsets[i]` is the index of prototype `i`'s first instruction.
    pub prototype_offsets: Vec<usize>,
}

#[derive(Debug)]
pub enum EncodeError {
    TooLong { count: usize },
}

pub fn encode_program(program: &CompiledProgram) -> Result<NoirBytecode, EncodeError> {
    // Concatenate all prototypes into a single flat instruction sequence.
    let count: usize = program.prototypes.iter().map(|p| p.code.len()).sum();
    if count > MAX_BYTECODE {
        return Err(EncodeError::TooLong { count });
    }

    let mut prototype_offsets = Vec::with_capacity(program.prototypes.len());
    let mut opcodes = [0u8; MAX_BYTECODE];
    let mut operands = [0i64; MAX_BYTECODE];
    let mut slot = 0usize;

    for proto in &program.prototypes {
        prototype_offsets.push(slot);
        for instr in &proto.code {
            opcodes[slot] = instruction_to_opcode_id(instr);
            operands[slot] = instruction_to_operand(instr);
            slot += 1;
        }
    }

    // The proveno-compiler already stores the Poseidon2 program hash on CompiledProgram
    // at compile time (see crate::proveno-compiler::program_hash). It is byte-identical
    // to what the circuit recomputes over (opcodes, operands), so we reuse it
    // here rather than hash twice — that guarantees there is exactly one
    // definition of "the program hash" in the Rust tree.
    let program_hash = program.program_hash;

    Ok(NoirBytecode {
        opcodes,
        operands,
        program_hash,
        instr_count: count,
        prototype_offsets,
    })
}

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
pub fn compute_program_hash(prototypes: &[crate::compiler::proto::FunctionProto]) -> [u8; 32] {
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
pub fn compute_program_hash_sha256(
    prototypes: &[crate::compiler::proto::FunctionProto],
) -> [u8; 32] {
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
    use crate::{compiler::compile, parser::parse};

    fn compile_lua(src: &str) -> CompiledProgram {
        compile(&parse(src).unwrap()).unwrap()
    }

    // ── SHA-256 program hash (zkVM backends) ─────────────────────────────────

    /// `PushK(i)` carries a pool index, so these three programs compile to the
    /// identical instruction stream. Only a hash that covers the constant pool
    /// can tell them apart, and this is exactly the substitution an attacker
    /// would attempt against a committed program hash.
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

    #[test]
    fn program_hash_is_stable() {
        // Compile the same source twice (two independent `CompiledProgram`s)
        // and assert both encodings produce identical program hashes. This
        // exercises the determinism of `compute_program_hash` end-to-end —
        // calling `encode_program` twice on the *same* `&program` would only
        // copy the precomputed `program.program_hash` field and degenerate
        // into `assert_eq!(x, x)`.
        let p1 = compile_lua("return 1 + 2");
        let p2 = compile_lua("return 1 + 2");
        let enc1 = encode_program(&p1).unwrap();
        let enc2 = encode_program(&p2).unwrap();
        assert_eq!(enc1.program_hash, enc2.program_hash);
    }

    #[test]
    fn program_hash_differs_for_different_programs() {
        let p1 = compile_lua("return 1 + 2");
        let p2 = compile_lua("local x = 0; for i = 1, 10 do x = x + i end; return x");
        let enc1 = encode_program(&p1).unwrap();
        let enc2 = encode_program(&p2).unwrap();
        assert_ne!(enc1.program_hash, enc2.program_hash);
    }

    #[test]
    fn padding_slots_are_zero() {
        let program = compile_lua("return 1 + 2");
        let enc = encode_program(&program).unwrap();
        assert!(enc.instr_count > 0);
        assert!(enc.instr_count <= MAX_BYTECODE);
        for i in enc.instr_count..MAX_BYTECODE {
            assert_eq!(
                enc.opcodes[i], 0,
                "padding opcode at slot {i} should be zero"
            );
            assert_eq!(
                enc.operands[i], 0,
                "padding operand at slot {i} should be zero"
            );
        }
    }

    #[test]
    fn loop_program_encodes_successfully() {
        let program = compile_lua("local x = 0; for i = 1, 10 do x = x + i end; return x");
        let enc = encode_program(&program).unwrap();
        assert!(enc.instr_count > 0);
        assert!(enc.instr_count <= MAX_BYTECODE);
    }

    #[test]
    fn multi_function_encodes_all_prototypes() {
        let src = "local function add(a, b) return a + b end; return add(1, 2)";
        let program = compile_lua(src);
        assert!(
            program.prototypes.len() >= 2,
            "expected at least 2 prototypes"
        );
        let enc = encode_program(&program).unwrap();
        let total: usize = program.prototypes.iter().map(|p| p.code.len()).sum();
        assert_eq!(enc.instr_count, total);
        assert_eq!(enc.prototype_offsets.len(), program.prototypes.len());
        assert_eq!(enc.prototype_offsets[0], 0);
        if program.prototypes.len() > 1 {
            assert_eq!(enc.prototype_offsets[1], program.prototypes[0].code.len());
        }
    }

    #[test]
    fn call_closure_pcall_encode_without_error() {
        let src = "local function f() return 1 end; return f()";
        let program = compile_lua(src);
        let enc = encode_program(&program).unwrap();
        assert!(enc.instr_count > 0);
    }
}
