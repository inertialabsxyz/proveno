pub mod codegen;
pub mod error;
pub mod proto;

pub use error::CompileError;
pub use proto::{CompiledProgram, Constant, FunctionProto, Instruction, UpvalueDesc};

use crate::parser::ast::Block;

/// Compile a parsed AST block into a `CompiledProgram`.
pub fn compile(block: &Block) -> Result<CompiledProgram, CompileError> {
    codegen::Compiler::compile(block)
}

// ---------------------------------------------------------------------------
// Program hash
// ---------------------------------------------------------------------------

/// Compute a deterministic SHA-256 hash over all function prototypes.
pub(crate) fn canonical_hash(prototypes: &[proto::FunctionProto]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in prototypes {
        canonical_encode_proto(p, &mut h);
    }
    h.finalize().into()
}

fn canonical_encode_proto<D: sha2::Digest>(proto: &proto::FunctionProto, h: &mut D) {
    // Number of instructions (u16 LE).
    let n_instr = proto.code.len() as u16;
    h.update(n_instr.to_le_bytes());

    // Each instruction: tag byte + operands.
    for instr in &proto.code {
        encode_instruction(instr, h);
    }

    // Constants.
    let n_const = proto.constants.len() as u16;
    h.update(n_const.to_le_bytes());
    for c in &proto.constants {
        encode_constant(c, h);
    }

    h.update([proto.param_count]);
    h.update([proto.upvalue_count]);
    h.update([proto.local_count]);

    let n_upvals = proto.upvalues.len() as u16;
    h.update(n_upvals.to_le_bytes());
    for upval in &proto.upvalues {
        match upval {
            proto::UpvalueDesc::Local(s) => {
                h.update([0u8, *s]);
            }
            proto::UpvalueDesc::Upvalue(s) => {
                h.update([1u8, *s]);
            }
        }
    }
}

fn encode_instruction<D: sha2::Digest>(instr: &proto::Instruction, h: &mut D) {
    use proto::Instruction::*;
    match instr {
        Nop => h.update([0]),
        PushK(x) => {
            h.update([1]);
            h.update(x.to_le_bytes());
        }
        PushNil => h.update([2]),
        PushTrue => h.update([3]),
        PushFalse => h.update([4]),
        Pop => h.update([5]),
        Dup => h.update([6]),
        LoadLocal(x) => {
            h.update([7]);
            h.update([*x]);
        }
        StoreLocal(x) => {
            h.update([8]);
            h.update([*x]);
        }
        LoadUp(x) => {
            h.update([9]);
            h.update([*x]);
        }
        StoreUp(x) => {
            h.update([10]);
            h.update([*x]);
        }
        NewTable => h.update([11]),
        GetTable => h.update([12]),
        SetTable => h.update([13]),
        GetField(x) => {
            h.update([14]);
            h.update(x.to_le_bytes());
        }
        SetField(x) => {
            h.update([15]);
            h.update(x.to_le_bytes());
        }
        Add => h.update([16]),
        Sub => h.update([17]),
        Mul => h.update([18]),
        IDiv => h.update([19]),
        Mod => h.update([20]),
        Neg => h.update([21]),
        Eq => h.update([22]),
        Ne => h.update([23]),
        Lt => h.update([24]),
        Le => h.update([25]),
        Gt => h.update([26]),
        Ge => h.update([27]),
        Not => h.update([28]),
        And(x) => {
            h.update([29]);
            h.update(x.to_le_bytes());
        }
        Or(x) => {
            h.update([30]);
            h.update(x.to_le_bytes());
        }
        Concat(x) => {
            h.update([31]);
            h.update([*x]);
        }
        Len => h.update([32]),
        Jmp(x) => {
            h.update([33]);
            h.update(x.to_le_bytes());
        }
        JmpIf(x) => {
            h.update([34]);
            h.update(x.to_le_bytes());
        }
        JmpIfNot(x) => {
            h.update([35]);
            h.update(x.to_le_bytes());
        }
        Call(x) => {
            h.update([36]);
            h.update([*x]);
        }
        Ret(x) => {
            h.update([37]);
            h.update([*x]);
        }
        Closure(x) => {
            h.update([38]);
            h.update(x.to_le_bytes());
        }
        ToolCall => h.update([39]),
        PCall(x) => {
            h.update([40]);
            h.update([*x]);
        }
        Log => h.update([41]),
        Error => h.update([42]),
        IterInitSorted(x) => {
            h.update([43]);
            h.update(x.to_le_bytes());
        }
        IterInitArray(x) => {
            h.update([44]);
            h.update(x.to_le_bytes());
        }
        IterNext(x) => {
            h.update([45]);
            h.update(x.to_le_bytes());
        }
    }
}

fn encode_constant<D: sha2::Digest>(c: &proto::Constant, h: &mut D) {
    use proto::Constant::*;
    match c {
        Nil => h.update([0]),
        Boolean(b) => {
            h.update([1]);
            h.update([*b as u8]);
        }
        Integer(n) => {
            h.update([2]);
            h.update(n.to_le_bytes());
        }
        String(s) => {
            h.update([3]);
            let len = s.len() as u32;
            h.update(len.to_le_bytes());
            h.update(s);
        }
        Proto(idx) => {
            h.update([4]);
            h.update(idx.to_le_bytes());
        }
    }
}
