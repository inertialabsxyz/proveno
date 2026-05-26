use std::io;
use std::path::Path;

use luai::noir::encoder::NoirBytecode;
use luai::noir::trace::TraceStep;
use luai::tls::TlsAttestationRecord;
use luai::types::value::LuaValue;
use luai::vm::engine::VmOutput;
use luai::zkvm::commitment::{hash_input, hash_output};
use luai::{OracleTape, TapeEntry};

pub const MAX_BYTECODE: usize = 512;
pub const MAX_STEPS: usize = 2048;
pub const MAX_TOOL_CALLS: usize = 16;
pub const MAX_TAPE_ENTRY_BYTES: usize = 1024;
pub const MAX_CERTS: usize = 4;

pub struct NoirWitness {
    pub bytecode_opcodes: [u8; MAX_BYTECODE],
    pub bytecode_operands: [i64; MAX_BYTECODE],
    pub instr_count: u32,
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
    // TLS attestation witnesses (zeroed when no verified certs)
    pub cert_public_key_x: [[u8; 32]; MAX_CERTS],
    pub cert_public_key_y: [[u8; 32]; MAX_CERTS],
    pub cert_signatures: [[u8; 64]; MAX_CERTS],
    pub cert_msg_hashes: [[u8; 32]; MAX_CERTS],
    pub num_certs: u32,
    // Additional public input hashes
    pub input_hash: [u8; 32],
    pub output_hash: [u8; 32],
    pub tls_attestation_hash: [u8; 32],
    pub policy_hash: [u8; 32],
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

/// Build a `NoirWitness` from all execution components.
///
/// Returns a heap-allocated witness to avoid placing ~480 KB of fixed-size
/// arrays on the test-thread stack (default 2 MB on macOS).
///
/// `tls_attestation_hash` is `[0u8; 32]` and `num_certs` is 0 for all inputs;
/// full TLS circuit witnesses are a future phase.
pub fn build_witness(
    bytecode: &NoirBytecode,
    trace: &[TraceStep],
    return_value: i64,
    oracle_tape: &OracleTape,
    input_value: &LuaValue,
    output: &VmOutput,
    _tls_attestations: &[TlsAttestationRecord],
    policy_hash: [u8; 32],
) -> Result<Box<NoirWitness>, WitnessError> {
    if trace.len() > MAX_STEPS {
        return Err(WitnessError::TraceTooLong { len: trace.len() });
    }

    // Allocate zeroed witness on the heap. NoirWitness contains only integer
    // arrays (u8/u32/i64), for which zero-initialisation is always valid.
    // Safety: NoirWitness contains only integer arrays (u8/u32/i64); zero is valid for all of them.
    let mut w: Box<NoirWitness> = unsafe { Box::<NoirWitness>::new_zeroed().assume_init() };

    // Bytecode.
    w.bytecode_opcodes = bytecode.opcodes;
    w.bytecode_operands = bytecode.operands;
    w.instr_count = bytecode.instr_count as u32;

    // Trace.
    w.num_steps = trace.len() as u32;
    for (i, step) in trace.iter().enumerate() {
        w.trace_pcs[i] = step.pc;
        w.trace_opcodes[i] = step.opcode;
        w.trace_operands[i] = step.operand;
        w.trace_stack_tops[i] = step.stack_top;
        w.trace_next_pcs[i] = step.next_pc;
    }

    // Scalar fields.
    w.program_hash = bytecode.program_hash;
    w.return_value = return_value;

    // Oracle tape.
    for (i, entry) in oracle_tape.entries.iter().enumerate().take(MAX_TOOL_CALLS) {
        match entry {
            TapeEntry::Ok(bytes) => {
                w.tape_entry_tags[i] = 0x00;
                let len = bytes.len().min(MAX_TAPE_ENTRY_BYTES);
                w.tape_entry_lengths[i] = len as u32;
                w.tape_entry_data[i][..len].copy_from_slice(&bytes[..len]);
            }
            TapeEntry::Err(msg) => {
                w.tape_entry_tags[i] = 0x01;
                let msg_bytes = msg.as_bytes();
                let len = msg_bytes.len().min(MAX_TAPE_ENTRY_BYTES);
                w.tape_entry_lengths[i] = len as u32;
                w.tape_entry_data[i][..len].copy_from_slice(&msg_bytes[..len]);
            }
        }
    }
    w.num_tool_calls = oracle_tape.entries.len().min(MAX_TOOL_CALLS) as u32;
    w.tool_responses_hash = oracle_tape.commitment_hash();

    // TLS: full P-256 cert witnesses are not yet wired up. The circuit takes
    // the num_certs == 0 branch and asserts tls_attestation_hash == [0; 32].
    w.num_certs = 0;
    w.tls_attestation_hash = [0u8; 32];

    // Public input hashes.
    w.input_hash = hash_input(input_value);
    w.output_hash = hash_output(output);
    w.policy_hash = policy_hash;

    Ok(w)
}

pub fn write_prover_toml(witness: &NoirWitness, path: &Path) -> io::Result<()> {
    let mut out = String::new();

    // Public inputs as top-level scalar/array keys.
    out.push_str(&format!("num_steps = {}\n", witness.num_steps));
    out.push_str(&format!("return_value = {}\n", witness.return_value));
    out.push_str(&format!(
        "program_hash = [{}]\n",
        bytes_toml(&witness.program_hash)
    ));
    out.push_str(&format!(
        "tool_responses_hash = [{}]\n",
        bytes_toml(&witness.tool_responses_hash)
    ));
    out.push_str(&format!(
        "input_hash = [{}]\n",
        bytes_toml(&witness.input_hash)
    ));
    out.push_str(&format!(
        "output_hash = [{}]\n",
        bytes_toml(&witness.output_hash)
    ));
    out.push_str(&format!(
        "tls_attestation_hash = [{}]\n",
        bytes_toml(&witness.tls_attestation_hash)
    ));
    out.push_str(&format!(
        "policy_hash = [{}]\n",
        bytes_toml(&witness.policy_hash)
    ));

    // Private witness arrays.
    out.push_str(&format!("instr_count = {}\n", witness.instr_count));
    out.push_str(&format!(
        "bytecode_opcodes = [{}]\n",
        bytes_toml(&witness.bytecode_opcodes)
    ));
    out.push_str(&format!(
        "bytecode_operands = [{}]\n",
        i64s_toml(&witness.bytecode_operands)
    ));
    out.push_str(&format!(
        "trace_pcs = [{}]\n",
        u32s_toml(&witness.trace_pcs)
    ));
    out.push_str(&format!(
        "trace_opcodes = [{}]\n",
        bytes_toml(&witness.trace_opcodes)
    ));
    out.push_str(&format!(
        "trace_operands = [{}]\n",
        i64s_toml(&witness.trace_operands)
    ));
    out.push_str(&format!(
        "trace_stack_tops = [{}]\n",
        i64s_toml(&witness.trace_stack_tops)
    ));
    out.push_str(&format!(
        "trace_next_pcs = [{}]\n",
        u32s_toml(&witness.trace_next_pcs)
    ));
    out.push_str(&format!("num_tool_calls = {}\n", witness.num_tool_calls));
    out.push_str(&format!(
        "tape_entry_tags = [{}]\n",
        bytes_toml(&witness.tape_entry_tags)
    ));
    out.push_str(&format!(
        "tape_entry_lengths = [{}]\n",
        u32s_toml(&witness.tape_entry_lengths)
    ));
    out.push_str(&format!(
        "tape_entry_data = [{}]\n",
        rows_toml(witness.tape_entry_data.iter().map(|r| r.as_slice()))
    ));

    out.push_str(&format!("num_certs = {}\n", witness.num_certs));
    out.push_str(&format!(
        "cert_public_key_x = [{}]\n",
        rows_toml(witness.cert_public_key_x.iter().map(|r| r.as_slice()))
    ));
    out.push_str(&format!(
        "cert_public_key_y = [{}]\n",
        rows_toml(witness.cert_public_key_y.iter().map(|r| r.as_slice()))
    ));
    out.push_str(&format!(
        "cert_signatures = [{}]\n",
        rows_toml(witness.cert_signatures.iter().map(|r| r.as_slice()))
    ));
    out.push_str(&format!(
        "cert_msg_hashes = [{}]\n",
        rows_toml(witness.cert_msg_hashes.iter().map(|r| r.as_slice()))
    ));

    std::fs::write(path, out)
}

fn bytes_toml(slice: &[u8]) -> String {
    slice
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn u32s_toml(slice: &[u32]) -> String {
    slice
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn i64s_toml(slice: &[i64]) -> String {
    slice
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn rows_toml<'a>(rows: impl Iterator<Item = &'a [u8]>) -> String {
    rows.map(|row| format!("[{}]", bytes_toml(row)))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use luai::compiler::compile;
    use luai::noir::encoder::encode_program;
    use luai::parser::parse;
    use luai::types::value::LuaValue;
    use luai::{NoopHost, OracleTape, Vm, VmConfig};

    fn run(src: &str) -> (NoirBytecode, VmOutput, i64) {
        let program = compile(&parse(src).unwrap()).unwrap();
        let bytecode = encode_program(&program).unwrap();
        let config = VmConfig {
            record_trace: true,
            ..VmConfig::default()
        };
        let output = Vm::new(config, NoopHost)
            .execute(&program, LuaValue::Nil)
            .unwrap();
        let return_val = match &output.return_value {
            LuaValue::Integer(n) => *n,
            _ => 0,
        };
        (bytecode, output, return_val)
    }

    #[test]
    fn build_witness_simple() {
        let (bytecode, output, ret) = run("return 1 + 2");
        assert!(!output.trace.is_empty());
        let tape = OracleTape::new();
        let witness = build_witness(
            &bytecode,
            &output.trace,
            ret,
            &tape,
            &LuaValue::Nil,
            &output,
            &[],
            [0u8; 32],
        )
        .unwrap();
        assert_eq!(witness.num_steps, output.trace.len() as u32);
        assert_eq!(witness.return_value, 3);
        assert_eq!(
            witness.bytecode_opcodes[0..bytecode.instr_count],
            bytecode.opcodes[0..bytecode.instr_count]
        );
        assert_eq!(witness.num_tool_calls, 0);
        assert_eq!(witness.num_certs, 0);
        assert_eq!(witness.tls_attestation_hash, [0u8; 32]);
        assert_eq!(witness.policy_hash, [0u8; 32]);
    }

    #[test]
    fn trace_too_long_returns_error() {
        let (bytecode, output, _) = run("return 1");
        let too_long: Vec<TraceStep> = (0..=MAX_STEPS)
            .map(|i| TraceStep {
                pc: i as u32,
                opcode: 0,
                operand: 0,
                stack_top: 0,
                next_pc: i as u32 + 1,
            })
            .collect();
        assert!(
            build_witness(
                &bytecode,
                &too_long,
                0,
                &OracleTape::new(),
                &LuaValue::Nil,
                &output,
                &[],
                [0u8; 32]
            )
            .is_err()
        );
    }

    #[test]
    fn write_prover_toml_roundtrip() {
        let (bytecode, output, ret) = run("return 42");
        let tape = OracleTape::new();
        let witness = build_witness(
            &bytecode,
            &output.trace,
            ret,
            &tape,
            &LuaValue::Nil,
            &output,
            &[],
            [0u8; 32],
        )
        .unwrap();
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
        assert!(contents.contains("input_hash = ["));
        assert!(contents.contains("output_hash = ["));
        assert!(contents.contains("tls_attestation_hash = ["));
        assert!(contents.contains("policy_hash = ["));
        assert!(contents.contains("num_certs ="));
        assert!(contents.contains("cert_public_key_x = ["));
        assert!(contents.contains("cert_signatures = ["));
    }

    #[test]
    fn build_witness_tape_fields_empty() {
        let (bytecode, output, ret) = run("return 1");
        let tape = OracleTape::new();
        let witness = build_witness(
            &bytecode,
            &output.trace,
            ret,
            &tape,
            &LuaValue::Nil,
            &output,
            &[],
            [0u8; 32],
        )
        .unwrap();
        assert_eq!(witness.num_tool_calls, 0);
        // Empty-tape commitment is the Poseidon2 sponge digest of zero leaves;
        // assert parity with the tape implementation rather than pinning bytes.
        assert_eq!(
            witness.tool_responses_hash,
            OracleTape::new().commitment_hash()
        );
    }

    #[test]
    fn input_hash_and_output_hash_are_nonzero() {
        let (bytecode, output, ret) = run("return 99");
        let tape = OracleTape::new();
        let witness = build_witness(
            &bytecode,
            &output.trace,
            ret,
            &tape,
            &LuaValue::Integer(7),
            &output,
            &[],
            [0u8; 32],
        )
        .unwrap();
        // input_hash = SHA-256("7") which is non-zero
        assert_ne!(witness.input_hash, [0u8; 32]);
        // output_hash is SHA-256 over return value bytes + (empty logs/transcript)
        assert_ne!(witness.output_hash, [0u8; 32]);
    }

    #[test]
    fn policy_hash_propagated() {
        let (bytecode, output, ret) = run("return 1");
        let tape = OracleTape::new();
        let policy = [0xABu8; 32];
        let witness = build_witness(
            &bytecode,
            &output.trace,
            ret,
            &tape,
            &LuaValue::Nil,
            &output,
            &[],
            policy,
        )
        .unwrap();
        assert_eq!(witness.policy_hash, policy);
    }
}
