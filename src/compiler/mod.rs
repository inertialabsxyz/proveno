pub mod codegen;
pub mod error;
pub mod proto;

pub use error::CompileError;
pub use proto::{CompiledProgram, Constant, FunctionProto, Instruction, UpvalueDesc};

use crate::parser::ast::Block;

/// Compile a parsed AST block into a `CompiledProgram`.
///
/// `CompiledProgram::program_hash` is the Poseidon2 hash that the Noir circuit
/// computes over the same `(opcode, operand)` field pairs (see
/// `crate::noir::encoder::compute_program_hash`). Keeping the two definitions
/// in lockstep is what lets the on-chain verifier accept a public-input
/// `program_hash` that the Rust caller supplied without recomputing.
pub fn compile(block: &Block) -> Result<CompiledProgram, CompileError> {
    codegen::Compiler::compile(block)
}
