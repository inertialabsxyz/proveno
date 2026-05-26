use poseidon::poseidon2::Poseidon2;
use sha256::sha256_var;

global MAX_BYTECODE: u32 = 512;
global MAX_STEPS: u32 = 2048;
global MAX_TOOL_CALLS: u32 = 16;
global MAX_TAPE_ENTRY_BYTES: u32 = 1024;
// Per-instruction Poseidon2 input pair: opcode field || operand field.
global MAX_BYTECODE_FIELDS: u32 = MAX_BYTECODE * 2;
// Per-entry Poseidon2 input vector: tag || len || payload bytes (one Field each).
global MAX_TAPE_ENTRY_FIELDS: u32 = MAX_TAPE_ENTRY_BYTES + 2;
global MAX_CERTS: u32 = 4;

// Decode a 32-byte big-endian array into a single Field. Mirrors
// `field_to_be_bytes32` on the Rust side, used to bridge the [u8; 32]
// public-input wire shape into the Field domain Poseidon2 operates in.
fn be_bytes32_to_field(bytes: [u8; 32]) -> Field {
    let mut acc: Field = 0;
    for i in 0..32 {
        acc = acc * 256 + bytes[i] as Field;
    }
    acc
}

fn assert_bytecode(
    bytecode_opcodes: [u8; MAX_BYTECODE],
    bytecode_operands: [i64; MAX_BYTECODE],
    instr_count: u32,
    program_hash: [u8; 32],
) {
    // Build [opcode_0, operand_0, opcode_1, operand_1, ...] over the full
    // MAX_BYTECODE buffer; live slots populate the first 2*instr_count fields,
    // padding stays zero. Negative i64 operands are reinterpreted as u64 to
    // match the Rust encoder's `(val as u64) as Field` widening.
    let mut hash_input: [Field; MAX_BYTECODE_FIELDS] = [0; MAX_BYTECODE_FIELDS];
    for i in 0..MAX_BYTECODE {
        hash_input[i * 2] = bytecode_opcodes[i] as Field;
        hash_input[i * 2 + 1] = (bytecode_operands[i] as u64) as Field;
    }

    let computed = Poseidon2::hash(hash_input, instr_count * 2);
    assert(computed == be_bytes32_to_field(program_hash));
}

fn main(
    bytecode_opcodes: [u8; MAX_BYTECODE],
    bytecode_operands: [i64; MAX_BYTECODE],
    instr_count: u32,
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
    assert_bytecode(
        bytecode_opcodes,
        bytecode_operands,
        instr_count,
        program_hash,
    );
    assert(trace_pcs[0] == 0);

    // 3-5. Single pass: verify each step's bytecode consistency, PC continuity,
    //      and return value. Count ToolCall opcodes to match against num_tool_calls.
    let mut tool_call_count: u32 = 0;
    for i in 0..MAX_STEPS {
        if (i as u32) < num_steps {
            let pc = trace_pcs[i];
            let opcode = trace_opcodes[i];
            let operand = trace_operands[i];
            let stack_top = trace_stack_tops[i];
            let next_pc = trace_next_pcs[i];

            // 3a. Opcode and operand must match bytecode at this pc.
            assert(opcode == bytecode_opcodes[pc]);
            assert(operand == bytecode_operands[pc]);
            assert(opcode <= 45);

            // 3b. Compute expected next_pc.
            let jmp_target = (pc as i64 + 1 + operand) as u32;
            let expected_next_pc = if opcode == 33 {
                jmp_target
            } else if (opcode == 34) & (stack_top != 0) {
                jmp_target
            } else if (opcode == 35) & (stack_top == 0) {
                jmp_target
            } else if (opcode == 29) & (stack_top == 0) {
                jmp_target
            } else if (opcode == 30) & (stack_top != 0) {
                jmp_target
            } else if (opcode == 43) & (stack_top == 0) {
                jmp_target
            } else if (opcode == 44) & (stack_top == 0) {
                jmp_target
            } else if (opcode == 45) & (stack_top == 0) {
                jmp_target
            } else {
                pc + 1
            };

            // Ret(37), Call(36), Closure(38), PCall(40): next_pc is unconstrained.
            let is_unconstrained =
                (opcode == 37) | (opcode == 36) | (opcode == 38) | (opcode == 40);
            if !is_unconstrained {
                assert(next_pc == expected_next_pc);
            }

            // 4. Step continuity.
            if (i as u32) + 1 < num_steps {
                assert(trace_pcs[i + 1] == trace_next_pcs[i]);
            }

            // 5. Return value: only the final step's Ret returns the program-level
            //    value. Inner Rets unwind nested call frames with their own
            //    intermediate values and must not be constrained here.
            if ((i as u32) + 1 == num_steps) & (opcode == 37) {
                assert(stack_top == return_value);
            }

            // 6. Count tool calls.
            if opcode == 39 {
                tool_call_count += 1;
            }
        }
    }

    // 7. Oracle tape: assert tool call count matches, then verify the tape hash
    //    using a two-level Poseidon2 scheme that matches `OracleTape::commitment_hash`:
    //
    //        leaf_i      = Poseidon2( tag, len, payload_byte_0, ..., payload_byte_{m-1} )
    //        commitment  = Poseidon2( leaf_0, leaf_1, ..., leaf_{n-1} )
    //
    //    Each per-entry input vector is laid out in a fixed-shape
    //    `[Field; MAX_TAPE_ENTRY_FIELDS]` buffer; only the first `len + 2`
    //    elements are part of the hash (via `Poseidon2::hash`'s `message_size`).
    //    Unused entry slots produce a leaf over a zero-padded buffer with
    //    `len + 2 = 2`, but the resulting leaf is overwritten in `leaves`
    //    only for live slots, so it can't leak into the outer commitment.
    assert(tool_call_count == num_tool_calls);
    let mut leaves: [Field; MAX_TOOL_CALLS] = [0; MAX_TOOL_CALLS];
    for i in 0..MAX_TOOL_CALLS {
        let len = tape_entry_lengths[i];
        let mut entry_fields: [Field; MAX_TAPE_ENTRY_FIELDS] = [0; MAX_TAPE_ENTRY_FIELDS];
        entry_fields[0] = tape_entry_tags[i] as Field;
        entry_fields[1] = len as Field;
        for j in 0..MAX_TAPE_ENTRY_BYTES {
            entry_fields[2 + j] = tape_entry_data[i][j] as Field;
        }
        leaves[i] = Poseidon2::hash(entry_fields, len + 2);
    }
    let computed = Poseidon2::hash(leaves, num_tool_calls);
    assert(computed == be_bytes32_to_field(tool_responses_hash));

    // 7. TLS attestation verification.
    //    For each cert i < num_certs: verify P-256 ECDSA signature.
    //    Accumulate a SHA-256 over the cert public keys (x || y per cert) in order,
    //    then assert the result equals tls_attestation_hash.
    //    When num_certs == 0, assert tls_attestation_hash is the zero array.
    let mut tls_flat: [u8; 256] = [0; 256]; // MAX_CERTS * 64
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
