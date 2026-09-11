pub mod codegen;
pub mod error;
pub mod proto;

pub use error::CompileError;
pub use proto::{CompiledProgram, Constant, FunctionProto, Instruction, UpvalueDesc};

use crate::parser::ast::Block;

/// Compile a parsed AST block into a `CompiledProgram`.
///
/// `CompiledProgram::program_hash` is computed over the flat `(opcode, operand)`
/// instruction stream. Under the default `poseidon` feature it is the Poseidon2
/// hash the Noir circuit recomputes over the same field pairs (see
/// `crate::noir::encoder::compute_program_hash`); keeping the two definitions in
/// lockstep is what lets the on-chain verifier accept a public-input
/// `program_hash` the Rust caller supplied without recomputing. Builds without
/// `poseidon` use `compute_program_hash_sha256` instead, for zkVM backends.
pub fn compile(block: &Block) -> Result<CompiledProgram, CompileError> {
    codegen::Compiler::compile(block)
}
