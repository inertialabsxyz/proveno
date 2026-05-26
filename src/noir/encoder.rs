use crate::{
    compiler::proto::CompiledProgram,
    host::poseidon2::{field_to_be_bytes32, i64_to_field, poseidon2_hash, u8_to_field},
};

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

    // Poseidon2 over interleaved (opcode_field, operand_field) for live
    // instructions only. Matches the circuit: Poseidon2::hash(inputs[2*instr_count]).
    // i64 operands are widened to u64 via the bit pattern (so -1 → u64::MAX),
    // mirroring how the Noir side coerces signed operands into Field.
    let mut inputs = Vec::with_capacity(count * 2);
    for i in 0..count {
        inputs.push(u8_to_field(opcodes[i]));
        inputs.push(i64_to_field(operands[i]));
    }
    let program_hash = field_to_be_bytes32(poseidon2_hash(&inputs));

    Ok(NoirBytecode {
        opcodes,
        operands,
        program_hash,
        instr_count: count,
        prototype_offsets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compiler::compile, parser::parse};

    fn compile_lua(src: &str) -> CompiledProgram {
        compile(&parse(src).unwrap()).unwrap()
    }

    #[test]
    fn program_hash_is_stable() {
        let program = compile_lua("return 1 + 2");
        let enc1 = encode_program(&program).unwrap();
        let enc2 = encode_program(&program).unwrap();
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
