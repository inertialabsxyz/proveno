//! Noir-backend encoding: the fixed-size bytecode ABI the circuit expects.
//!
//! Backend-specific, unlike [`crate::isa`]: `MAX_BYTECODE` here must match
//! `global MAX_BYTECODE` in `noir/src/main.nr`.
pub mod encoder;
