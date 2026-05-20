global MAX_BYTECODE: u32 = 512;
global MAX_STEPS: u32 = 16384;
global MAX_TOOL_CALLS: u32 = 64;
global MAX_TAPE_ENTRY_BYTES: u32 = 1024;
// 64 entries * (1 tag + 4 length bytes + 1024 payload bytes) = 65856
global MAX_CERTS: u32 = 4;

use sha256::digest;
use sha256::sha256_var;

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
    tape_entry_tags: [u8; MAX_TOOL_CALLS],
    tape_entry_lengths: [u32; MAX_TOOL_CALLS],
    tape_entry_data: [[u8; MAX_TAPE_ENTRY_BYTES]; MAX_TOOL_CALLS],
    num_tool_calls: u32,
    tool_responses_hash: pub [u8; 32],
    input_hash: pub [u8; 32],
    output_hash: pub [u8; 32],
    tls_attestation_hash: pub [u8; 32],
    policy_hash: pub [u8; 32],
    cert_public_key_x: [[u8; 32]; MAX_CERTS],
    cert_public_key_y: [[u8; 32]; MAX_CERTS],
    cert_signatures: [[u8; 64]; MAX_CERTS],
    cert_msg_hashes: [[u8; 32]; MAX_CERTS],
    num_certs: u32,
) {
    // 1. Verify program hash: SHA-256 over (opcode || operand LE) for all MAX_BYTECODE slots.
    //    Unused slots are padded with opcode=0, operand=0 by the host.
    let mut hash_input: [u8; 4608] = [0; 4608]; // MAX_BYTECODE * 9
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
            assert(opcode <= 45);

            // Compute expected next_pc. Jump target = pc + 1 + operand (i16 signed offset).
            let jmp_target = (pc as i64 + 1 + operand) as u32;
            let expected_next_pc = if opcode == 33 {
                // Jmp(33): always jump
                jmp_target
            } else if (opcode == 34) & (stack_top != 0) {
                // JmpIf(34): jump when non-zero
                jmp_target
            } else if (opcode == 35) & (stack_top == 0) {
                // JmpIfNot(35): jump when zero
                jmp_target
            } else if (opcode == 29) & (stack_top == 0) {
                // And(29): short-circuit jump when zero
                jmp_target
            } else if (opcode == 30) & (stack_top != 0) {
                // Or(30): short-circuit jump when non-zero
                jmp_target
            } else if (opcode == 43) & (stack_top == 0) {
                // IterInitSorted(43): jump when empty
                jmp_target
            } else if (opcode == 44) & (stack_top == 0) {
                // IterInitArray(44): jump when empty
                jmp_target
            } else if (opcode == 45) & (stack_top == 0) {
                // IterNext(45): jump when exhausted
                jmp_target
            } else {
                pc + 1
            };

            // Ret(37), Call(36), Closure(38), PCall(40): next_pc is unconstrained.
            let is_unconstrained = (opcode == 37) | (opcode == 36) | (opcode == 38) | (opcode == 40);
            if !is_unconstrained {
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

    // 5. Return value: the stack_top at the Ret(37) step must equal return_value.
    //    This closes the trust gap the prover cannot fabricate a trace that
    //    claims a different output than the program actually produced.
    for i in 0..MAX_STEPS {
        if (i as u32) < num_steps {
            if trace_opcodes[i] == 37 {
                assert(trace_stack_tops[i] == return_value);
            }
        }
    }

    // 6. Oracle tape verification: rebuild the commitment hash from witness tape entries
    //    and assert it matches tool_responses_hash.
    //
    //    Framing matches OracleTape::commitment_hash():
    //      for each entry: tag (1 byte) || length (4 bytes LE) || payload
    //    We pack entries into a flat byte array without inter-entry padding, then
    //    hash the first byte_cursor bytes using sha256_var.
    let mut flat: [u8; 65856] = [0; 65856];
    let mut byte_cursor: u32 = 0;
    let mut tape_cursor: u32 = 0;

    for i in 0..MAX_STEPS {
        if (i as u32) < num_steps {
            if trace_opcodes[i] == 39 {
                // ToolCall(39): consume next tape entry.
                let tag = tape_entry_tags[tape_cursor];
                let len = tape_entry_lengths[tape_cursor];
                let data = tape_entry_data[tape_cursor];

                // Write tag byte.
                flat[byte_cursor] = tag;
                byte_cursor += 1;

                // Write 4-byte little-endian length.
                flat[byte_cursor] = (len & 0xFF) as u8;
                flat[byte_cursor + 1] = ((len >> 8) & 0xFF) as u8;
                flat[byte_cursor + 2] = ((len >> 16) & 0xFF) as u8;
                flat[byte_cursor + 3] = ((len >> 24) & 0xFF) as u8;
                byte_cursor += 4;

                // Write payload bytes (only the first `len` bytes of the padded entry).
                for j in 0..MAX_TAPE_ENTRY_BYTES {
                    if j < len {
                        flat[byte_cursor] = data[j];
                        byte_cursor += 1;
                    }
                }

                tape_cursor += 1;
            }
        }
    }

    // Assert num_tool_calls matches the number of ToolCall steps we counted.
    assert(tape_cursor == num_tool_calls);

    // Hash exactly byte_cursor bytes and compare to the committed tool_responses_hash.
    let computed_hash = sha256_var(flat, byte_cursor as u64);
    assert(computed_hash == tool_responses_hash);

    // 7. TLS attestation verification.
    //    For each cert i < num_certs: verify P-256 ECDSA signature.
    //    Accumulate a SHA-256 over the cert public keys (x || y per cert) in order,
    //    then assert the result equals tls_attestation_hash.
    //    When num_certs == 0, assert tls_attestation_hash is the zero array.
    //
    //    MAX_CERTS * 64 = 256 bytes
    let mut tls_flat: [u8; 256] = [0; 256];
    for i in 0..MAX_CERTS {
        if (i as u32) < num_certs {
            assert(std::ecdsa_secp256r1::verify_signature(
                cert_public_key_x[i],
                cert_public_key_y[i],
                cert_signatures[i],
                cert_msg_hashes[i],
            ));
            for j in 0..32 {
                tls_flat[i * 64 + j] = cert_public_key_x[i][j];
                tls_flat[i * 64 + 32 + j] = cert_public_key_y[i][j];
            }
        }
    }
    if num_certs == 0 {
        for j in 0..32 {
            assert(tls_attestation_hash[j] == 0);
        }
    } else {
        let computed_tls_hash = sha256_var(tls_flat, (num_certs * 64) as u64);
        assert(computed_tls_hash == tls_attestation_hash);
    }
}
