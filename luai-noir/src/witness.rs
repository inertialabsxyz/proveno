use std::io;
use std::path::Path;

use luai::noir::encoder::NoirBytecode;
use luai::noir::trace::TraceStep;
use luai::{OracleTape, TapeEntry};

pub const MAX_BYTECODE: usize = 512;
pub const MAX_STEPS: usize = 16384;
pub const MAX_TOOL_CALLS: usize = 64;
pub const MAX_TAPE_ENTRY_BYTES: usize = 1024;

pub struct NoirWitness {
    pub bytecode_opcodes: [u8; MAX_BYTECODE],
    pub bytecode_operands: [i64; MAX_BYTECODE],
    pub trace_pcs: [u32; MAX_STEPS],
    pub trace_opcodes: [u8; MAX_STEPS],
    pub trace_operands: [i64; MAX_STEPS],
    pub trace_stack_tops: [i64; MAX_STEPS],
    pub trace_next_pcs: [u32; MAX_STEPS],
    pub num_steps: u32,
    pub program_hash: [u8; 32],
    pub return_value: i64,
    pub tape_entry_tags: [u8; MAX_TOOL_CALLS],
    pub tape_entry_lengths: [u32; MAX_TOOL_CALLS],
    pub tape_entry_data: [[u8; MAX_TAPE_ENTRY_BYTES]; MAX_TOOL_CALLS],
    pub num_tool_calls: u32,
    pub tool_responses_hash: [u8; 32],
}

#[derive(Debug)]
pub enum WitnessError {
    TraceTooLong { len: usize },
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WitnessError::TraceTooLong { len } => {
                write!(f, "trace length {len} exceeds MAX_STEPS ({MAX_STEPS})")
            }
        }
    }
}

impl std::error::Error for WitnessError {}

pub fn build_witness(
    bytecode: &NoirBytecode,
    trace: &[TraceStep],
    return_value: i64,
    oracle_tape: &OracleTape,
) -> Result<NoirWitness, WitnessError> {
    if trace.len() > MAX_STEPS {
        return Err(WitnessError::TraceTooLong { len: trace.len() });
    }

    let mut trace_pcs = [0u32; MAX_STEPS];
    let mut trace_opcodes = [0u8; MAX_STEPS];
    let mut trace_operands = [0i64; MAX_STEPS];
    let mut trace_stack_tops = [0i64; MAX_STEPS];
    let mut trace_next_pcs = [0u32; MAX_STEPS];

    for (i, step) in trace.iter().enumerate() {
        trace_pcs[i] = step.pc;
        trace_opcodes[i] = step.opcode;
        trace_operands[i] = step.operand;
        trace_stack_tops[i] = step.stack_top;
        trace_next_pcs[i] = step.next_pc;
    }

    let mut tape_entry_tags = [0u8; MAX_TOOL_CALLS];
    let mut tape_entry_lengths = [0u32; MAX_TOOL_CALLS];
    let mut tape_entry_data = [[0u8; MAX_TAPE_ENTRY_BYTES]; MAX_TOOL_CALLS];

    for (i, entry) in oracle_tape.entries.iter().enumerate().take(MAX_TOOL_CALLS) {
        match entry {
            TapeEntry::Ok(bytes) => {
                tape_entry_tags[i] = 0x00;
                let len = bytes.len().min(MAX_TAPE_ENTRY_BYTES);
                tape_entry_lengths[i] = len as u32;
                tape_entry_data[i][..len].copy_from_slice(&bytes[..len]);
            }
            TapeEntry::Err(msg) => {
                tape_entry_tags[i] = 0x01;
                let msg_bytes = msg.as_bytes();
                let len = msg_bytes.len().min(MAX_TAPE_ENTRY_BYTES);
                tape_entry_lengths[i] = len as u32;
                tape_entry_data[i][..len].copy_from_slice(&msg_bytes[..len]);
            }
        }
    }

    let num_tool_calls = oracle_tape.entries.len().min(MAX_TOOL_CALLS) as u32;
    let tool_responses_hash = oracle_tape.commitment_hash();

    Ok(NoirWitness {
        bytecode_opcodes: bytecode.opcodes,
        bytecode_operands: bytecode.operands,
        trace_pcs,
        trace_opcodes,
        trace_operands,
        trace_stack_tops,
        trace_next_pcs,
        num_steps: trace.len() as u32,
        program_hash: bytecode.program_hash,
        return_value,
        tape_entry_tags,
        tape_entry_lengths,
        tape_entry_data,
        num_tool_calls,
        tool_responses_hash,
    })
}

pub fn write_prover_toml(witness: &NoirWitness, path: &Path) -> io::Result<()> {
    let mut out = String::new();

    // Public inputs as top-level scalar keys.
    out.push_str(&format!("num_steps = {}\n", witness.num_steps));
    out.push_str(&format!("return_value = {}\n", witness.return_value));
    out.push_str(&format!(
        "program_hash = [{}]\n",
        witness
            .program_hash
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!(
        "tool_responses_hash = [{}]\n",
        witness
            .tool_responses_hash
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));

    // Private witness arrays.
    out.push_str(&format!(
        "bytecode_opcodes = [{}]\n",
        witness
            .bytecode_opcodes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!(
        "bytecode_operands = [{}]\n",
        witness
            .bytecode_operands
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!(
        "trace_pcs = [{}]\n",
        witness
            .trace_pcs
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!(
        "trace_opcodes = [{}]\n",
        witness
            .trace_opcodes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!(
        "trace_operands = [{}]\n",
        witness
            .trace_operands
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!(
        "trace_stack_tops = [{}]\n",
        witness
            .trace_stack_tops
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!(
        "trace_next_pcs = [{}]\n",
        witness
            .trace_next_pcs
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!("num_tool_calls = {}\n", witness.num_tool_calls));
    out.push_str(&format!(
        "tape_entry_tags = [{}]\n",
        witness
            .tape_entry_tags
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!(
        "tape_entry_lengths = [{}]\n",
        witness
            .tape_entry_lengths
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));

    // 2D array: array of inline arrays, one per tape entry.
    let rows: Vec<String> = witness
        .tape_entry_data
        .iter()
        .map(|row| {
            format!(
                "[{}]",
                row.iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect();
    out.push_str(&format!("tape_entry_data = [{}]\n", rows.join(", ")));

    std::fs::write(path, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use luai::compiler::compile;
    use luai::noir::encoder::encode_program;
    use luai::parser::parse;
    use luai::{NoopHost, OracleTape, Vm, VmConfig};

    fn run(src: &str) -> (NoirBytecode, Vec<TraceStep>, i64) {
        let program = compile(&parse(src).unwrap()).unwrap();
        let bytecode = encode_program(&program).unwrap();
        let config = VmConfig {
            record_trace: true,
            ..VmConfig::default()
        };
        let output = Vm::new(config, NoopHost)
            .execute(&program, luai::types::value::LuaValue::Nil)
            .unwrap();
        let return_val = match output.return_value {
            luai::types::value::LuaValue::Integer(n) => n,
            _ => 0,
        };
        (bytecode, output.trace, return_val)
    }

    #[test]
    fn build_witness_simple() {
        let (bytecode, trace, ret) = run("return 1 + 2");
        assert!(!trace.is_empty());
        let tape = OracleTape::new();
        let witness = build_witness(&bytecode, &trace, ret, &tape).unwrap();
        assert_eq!(witness.num_steps, trace.len() as u32);
        assert_eq!(witness.return_value, 3);
        assert_eq!(
            witness.bytecode_opcodes[0..bytecode.instr_count],
            bytecode.opcodes[0..bytecode.instr_count]
        );
        assert_eq!(witness.num_tool_calls, 0);
    }

    #[test]
    fn trace_too_long_returns_error() {
        let (bytecode, _, _) = run("return 1");
        let too_long: Vec<TraceStep> = (0..=MAX_STEPS)
            .map(|i| TraceStep {
                pc: i as u32,
                opcode: 0,
                operand: 0,
                stack_top: 0,
                next_pc: i as u32 + 1,
            })
            .collect();
        assert!(build_witness(&bytecode, &too_long, 0, &OracleTape::new()).is_err());
    }

    #[test]
    fn write_prover_toml_roundtrip() {
        let (bytecode, trace, ret) = run("return 42");
        let tape = OracleTape::new();
        let witness = build_witness(&bytecode, &trace, ret, &tape).unwrap();
        let dir = std::env::temp_dir();
        let path = dir.join("test_prover.toml");
        write_prover_toml(&witness, &path).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("return_value = 42"));
        assert!(contents.contains("num_steps ="));
        assert!(contents.contains("program_hash = ["));
        assert!(contents.contains("bytecode_opcodes = ["));
        assert!(contents.contains("trace_pcs = ["));
        assert!(contents.contains("tool_responses_hash = ["));
        assert!(contents.contains("tape_entry_data = ["));
    }

    #[test]
    fn build_witness_tape_fields_empty() {
        let (bytecode, trace, ret) = run("return 1");
        let tape = OracleTape::new();
        let witness = build_witness(&bytecode, &trace, ret, &tape).unwrap();
        assert_eq!(witness.num_tool_calls, 0);
        // SHA-256 of empty input
        let expected_hash: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(witness.tool_responses_hash, expected_hash);
    }
}
