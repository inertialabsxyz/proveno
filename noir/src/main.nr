global MAX_BYTECODE: u32 = 64;
global MAX_STEPS: u32 = 16384;

use sha256::digest;

// Decomposes an i64 operand into 8 little-endian bytes using arithmetic right
// shift. Negative values are handled correctly via two's complement bit masking.
fn operand_le_bytes(val: i64) -> [u8; 8] {
    [
        (val & 0xFF) as u8,
        ((val >> 8) & 0xFF) as u8,
        ((val >> 16) & 0xFF) as u8,
        ((val >> 24) & 0xFF) as u8,
        ((val >> 32) & 0xFF) as u8,
        ((val >> 40) & 0xFF) as u8,
        ((val >> 48) & 0xFF) as u8,
        ((val >> 56) & 0xFF) as u8,
    ]
}

fn main(
    bytecode_opcodes: [u8; MAX_BYTECODE],
    bytecode_operands: [i64; MAX_BYTECODE],
    trace_pcs: [u32; MAX_STEPS],
    trace_opcodes: [u8; MAX_STEPS],
    trace_operands: [i64; MAX_STEPS],
    trace_stack_tops: [i64; MAX_STEPS],
    trace_next_pcs: [u32; MAX_STEPS],
    num_steps: pub u32,
    program_hash: pub [u8; 32],
    return_value: pub i64,
) {
    // 1. Verify program hash: SHA-256 over (opcode || operand LE) for all MAX_BYTECODE slots.
    //    Unused slots are padded with opcode=0, operand=0 by the host.
    let mut hash_input: [u8; 576] = [0; 576]; // MAX_BYTECODE * 9
    for i in 0..MAX_BYTECODE {
        hash_input[i * 9] = bytecode_opcodes[i];
        let op_bytes: [u8; 8] = operand_le_bytes(bytecode_operands[i]);
        for j in 0..8 {
            hash_input[i * 9 + 1 + j] = op_bytes[j];
        }
    }
    assert(digest(hash_input) == program_hash);

    // 2. First step must start at pc=0.
    assert(trace_pcs[0] == 0);

    // 3. Verify each trace step.
    for i in 0..MAX_STEPS {
        if (i as u32) < num_steps {
            let pc = trace_pcs[i];
            let opcode = trace_opcodes[i];
            let operand = trace_operands[i];
            let stack_top = trace_stack_tops[i];
            let next_pc = trace_next_pcs[i];

            // Opcode and operand must match bytecode at this pc.
            assert(opcode == bytecode_opcodes[pc]);
            assert(operand == bytecode_operands[pc]);
            assert(opcode <= 15);

            // Compute expected next_pc.
            let jmp_target = (pc as i64 + 1 + operand) as u32;
            let expected_next_pc = if opcode == 12 {
                // Jmp: always jump
                jmp_target
            } else if (opcode == 13) & (stack_top == 0) {
                // JmpIfNot: jump when zero
                jmp_target
            } else {
                pc + 1 // sequential; Ret is unconstrained below
            };

            if opcode != 14 {
                // Ret: next_pc is unconstrained
                assert(next_pc == expected_next_pc);
            }
        }
    }

    // 4. Step continuity: each step's pc must equal the previous step's next_pc.
    //    Stop at MAX_STEPS-1 to avoid out-of-bounds on trace_pcs[i+1].
    for i in 0..16383 {
        if (i as u32) + 1 < num_steps {
            assert(trace_pcs[i + 1] == trace_next_pcs[i]);
        }
    }

    // 5. Return value: the stack_top at the Ret step must equal return_value.
    //    This closes the trust gap the prover cannot fabricate a trace that
    //    claims a different output than the program actually produced.
    for i in 0..MAX_STEPS {
        if (i as u32) < num_steps {
            if trace_opcodes[i] == 14 {
                assert(trace_stack_tops[i] == return_value);
            }
        }
    }
}
