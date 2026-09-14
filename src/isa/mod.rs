//! The VM's instruction encoding: opcode numbering and the execution trace.
//!
//! This is the VM's own ISA, not a prover concern. It lived under `noir`
//! because the Noir circuit was the first consumer of the numbering, which made
//! the compiler look as though it depended on a proving backend. Any backend
//! that needs to talk about instructions talks about these.
pub mod opcodes;
pub mod trace;
