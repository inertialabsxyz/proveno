//! `GuestInput` — the serializable bundle fed into the zkVM guest.
//!
//! The guest reads one `GuestInput`, re-executes the program with a `TapeHost`
//! for tool calls, computes the `PublicInputs`, and commits them to the journal.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::{
    compiler::proto::CompiledProgram, host::tape::OracleTape, types::value::LuaValue,
    vm::engine::VmConfig,
};

/// Everything the zkVM guest needs to replay an agent execution deterministically.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GuestInput {
    /// The compiled Lua program (bytecode + program_hash).
    pub program: CompiledProgram,
    /// The input value passed to the program's top-level function.
    pub input_value: LuaValue,
    /// Pre-recorded oracle tape of tool responses.
    pub oracle_tape: OracleTape,
    /// VM resource limits (must be identical to the dry-run config).
    pub config: VmConfig,
    /// Tool names registered in the dry run (used to build the ToolRegistry inside the guest).
    pub tool_names: Vec<String>,
}

impl GuestInput {
    pub fn new(
        program: CompiledProgram,
        input_value: LuaValue,
        oracle_tape: OracleTape,
        config: VmConfig,
        tool_names: Vec<String>,
    ) -> Self {
        GuestInput {
            program,
            input_value,
            oracle_tape,
            config,
            tool_names,
        }
    }
}
