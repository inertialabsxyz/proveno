#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod host;
pub mod types;
pub mod vm;
pub mod parser;
pub mod compiler;
pub mod bytecode;
pub mod tls;
pub mod policy;

#[cfg(feature = "zkvm")]
pub mod zkvm;

pub use vm::engine::{Vm, VmConfig, VmOutput, HostInterface, NoopHost};
pub use vm::gas::{GasMeter, VmError};
pub use vm::memory::MemoryMeter;
pub use host::transcript::{ToolCallRecord, ToolCallStatus, Transcript};
pub use host::tape::{OracleTape, TapeEntry, TapeHost};

pub fn execute(
    program: &compiler::proto::CompiledProgram,
    input: types::value::LuaValue,
    config: VmConfig,
) -> Result<VmOutput, VmError> {
    let mut vm = Vm::new(config, NoopHost);
    vm.execute(program, input)
}
