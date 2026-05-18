#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod bytecode;
pub mod compiler;
pub mod host;
pub mod parser;
pub mod policy;
pub mod tls;
pub mod types;
pub mod vm;

#[cfg(feature = "zkvm")]
pub mod zkvm;

pub use host::tape::{OracleTape, TapeEntry, TapeHost};
pub use host::transcript::{ToolCallRecord, ToolCallStatus, Transcript};
pub use vm::engine::{HostInterface, NoopHost, Vm, VmConfig, VmOutput};
pub use vm::gas::{GasMeter, VmError};
pub use vm::memory::MemoryMeter;

pub fn execute(
    program: &compiler::proto::CompiledProgram,
    input: types::value::LuaValue,
    config: VmConfig,
) -> Result<VmOutput, VmError> {
    let mut vm = Vm::new(config, NoopHost);
    vm.execute(program, input)
}
