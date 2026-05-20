use sha2::{Digest, Sha256};

use crate::compiler::proto::{CompiledProgram, Instruction};

use super::opcodes::{instruction_to_opcode_id, instruction_to_operand};

pub const MAX_BYTECODE: usize = 512;

pub struct NoirBytecode {
    pub opcodes: [u8; MAX_BYTECODE],
    pub operands: [i64; MAX_BYTECODE],
    pub program_hash: [u8; 32],
    pub instr_count: usize,
}

#[derive(Debug)]
pub enum EncodeError {
    TooLong { count: usize },
    CallNotSupported,
}

pub fn encode_program(program: &CompiledProgram) -> Result<NoirBytecode, EncodeError> {
    let code = &program.prototypes[0].code;

    for instr in code {
        match instr {
            Instruction::Call(_) | Instruction::Closure(_) | Instruction::PCall(_) => {
                return Err(EncodeError::CallNotSupported);
            }
            _ => {}
        }
    }

    let count = code.len();
    if count > MAX_BYTECODE {
        return Err(EncodeError::TooLong { count });
    }

    let mut opcodes = [0u8; MAX_BYTECODE];
    let mut operands = [0i64; MAX_BYTECODE];

    for (i, instr) in code.iter().enumerate() {
        opcodes[i] = instruction_to_opcode_id(instr);
        operands[i] = instruction_to_operand(instr);
    }

    // SHA-256 over (opcode_byte || operand_le_8bytes) for all MAX_BYTECODE slots,
    // including zero-padded slots, so the hash commits to the full fixed-length encoding.
    let mut hasher = Sha256::new();
    for i in 0..MAX_BYTECODE {
        hasher.update([opcodes[i]]);
        hasher.update(operands[i].to_le_bytes());
    }
    let program_hash: [u8; 32] = hasher.finalize().into();

    Ok(NoirBytecode {
        opcodes,
        operands,
        program_hash,
        instr_count: count,
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
}
