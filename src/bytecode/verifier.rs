use crate::compiler::proto::{CompiledProgram, Constant, FunctionProto, Instruction};
#[cfg(not(feature = "std"))]
use alloc::{collections::VecDeque, vec, vec::Vec};
#[cfg(feature = "std")]
use std::collections::VecDeque;

pub const MAX_STACK_DEPTH: usize = 256;

/// Errors produced by the bytecode verifier.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyError {
    /// Constant pool index out of bounds.
    ConstantIndexOob { proto: u16, pc: usize, index: u16 },

    /// Prototype index out of bounds (CLOSURE operand).
    ProtoIndexOob { proto: u16, pc: usize, index: u16 },

    /// LOADUP / STOREUP index >= upvalue_count.
    UpvalueIndexOob { proto: u16, pc: usize, index: u8 },

    /// Jump target is outside [0, code.len()].
    JumpOutOfRange {
        proto: u16,
        pc: usize,
        target: usize,
    },

    /// Stack depth went negative.
    StackUnderflow { proto: u16, pc: usize },

    /// Stack depth exceeded MAX_STACK_DEPTH.
    StackOverflow { proto: u16, pc: usize, depth: usize },

    /// Two paths to the same instruction disagree on stack depth.
    StackDepthMismatch {
        proto: u16,
        pc: usize,
        expected: usize,
        got: usize,
    },

    /// RET instruction has wrong stack depth vs declared return count.
    RetStackMismatch {
        proto: u16,
        pc: usize,
        expected: usize,
        got: usize,
    },

    /// Prototype reference graph contains a cycle.
    PrototypeCycle { proto: u16 },
}

/// Verify all prototypes in a compiled program before execution.
pub fn verify(program: &CompiledProgram) -> Result<(), VerifyError> {
    check_proto_dag(program)?;
    for (idx, proto) in program.prototypes.iter().enumerate() {
        verify_proto(program, idx as u16, proto)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DAG check
// ---------------------------------------------------------------------------

fn check_proto_dag(program: &CompiledProgram) -> Result<(), VerifyError> {
    let n = program.prototypes.len();
    // Build adjacency list: edges[i] = set of proto indices referenced by proto i.
    let mut adj: Vec<Vec<u16>> = vec![Vec::new(); n];
    for (i, proto) in program.prototypes.iter().enumerate() {
        for c in &proto.constants {
            if let Constant::Proto(idx) = c {
                adj[i].push(*idx);
            }
        }
    }

    // Three-colour DFS: 0 = white, 1 = grey (in stack), 2 = black (done).
    let mut color = vec![0u8; n];

    for start in 0..n {
        if color[start] != 0 {
            continue;
        }
        // Iterative DFS using an explicit stack of (node, edge_index).
        let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
        color[start] = 1;

        while let Some((node, edge_idx)) = stack.last_mut() {
            let node = *node;
            if *edge_idx < adj[node].len() {
                let child = adj[node][*edge_idx] as usize;
                *edge_idx += 1;
                if child >= n {
                    // Invalid proto ref — will be caught in structural checks.
                    continue;
                }
                match color[child] {
                    1 => {
                        // Back edge → cycle.
                        return Err(VerifyError::PrototypeCycle {
                            proto: child as u16,
                        });
                    }
                    0 => {
                        color[child] = 1;
                        stack.push((child, 0));
                    }
                    _ => {} // already processed
                }
            } else {
                color[node] = 2;
                stack.pop();
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-prototype verification
// ---------------------------------------------------------------------------

fn verify_proto(
    program: &CompiledProgram,
    proto_idx: u16,
    proto: &FunctionProto,
) -> Result<(), VerifyError> {
    structural_checks(program, proto_idx, proto)?;
    stack_analysis(proto_idx, proto)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Structural checks
// ---------------------------------------------------------------------------

fn structural_checks(
    program: &CompiledProgram,
    proto_idx: u16,
    proto: &FunctionProto,
) -> Result<(), VerifyError> {
    let const_len = proto.constants.len();
    let code_len = proto.code.len();
    let proto_count = program.prototypes.len();

    for (pc, instr) in proto.code.iter().enumerate() {
        match instr {
            // Constant index checks
            Instruction::PushK(idx) => {
                if *idx as usize >= const_len {
                    return Err(VerifyError::ConstantIndexOob {
                        proto: proto_idx,
                        pc,
                        index: *idx,
                    });
                }
            }
            Instruction::GetField(idx) | Instruction::SetField(idx) => {
                if *idx as usize >= const_len {
                    return Err(VerifyError::ConstantIndexOob {
                        proto: proto_idx,
                        pc,
                        index: *idx,
                    });
                }
            }

            // Prototype index check
            Instruction::Closure(idx) => {
                if *idx as usize >= proto_count {
                    return Err(VerifyError::ProtoIndexOob {
                        proto: proto_idx,
                        pc,
                        index: *idx,
                    });
                }
            }

            // Upvalue index checks
            Instruction::LoadUp(idx) | Instruction::StoreUp(idx) => {
                if *idx >= proto.upvalue_count {
                    return Err(VerifyError::UpvalueIndexOob {
                        proto: proto_idx,
                        pc,
                        index: *idx,
                    });
                }
            }

            // Jump target checks
            Instruction::Jmp(off)
            | Instruction::JmpIf(off)
            | Instruction::JmpIfNot(off)
            | Instruction::And(off)
            | Instruction::Or(off) => {
                check_jump_target(proto_idx, pc, *off, code_len)?;
            }
            Instruction::IterInitSorted(off)
            | Instruction::IterInitArray(off)
            | Instruction::IterNext(off) => {
                check_jump_target(proto_idx, pc, *off, code_len)?;
            }

            // All other instructions need no structural operand checks.
            _ => {}
        }
    }
    Ok(())
}

fn check_jump_target(
    proto_idx: u16,
    pc: usize,
    offset: i16,
    code_len: usize,
) -> Result<(), VerifyError> {
    let target = jump_target(pc, offset, code_len);
    match target {
        Some(_) => Ok(()),
        None => {
            // Compute the raw target for the error message.
            let raw = (pc as isize + 1 + offset as isize) as usize;
            Err(VerifyError::JumpOutOfRange {
                proto: proto_idx,
                pc,
                target: raw,
            })
        }
    }
}

/// Compute jump target, returning None if out of range.
/// Valid range: [0, code_len] (inclusive — landing past last instruction is ok
/// for forward jumps that exit the function).
fn jump_target(pc: usize, offset: i16, code_len: usize) -> Option<usize> {
    let base = pc as isize + 1;
    let target = base.checked_add(offset as isize)?;
    if target < 0 || target as usize > code_len {
        return None;
    }
    Some(target as usize)
}

// ---------------------------------------------------------------------------
// Stack depth abstract interpretation
// ---------------------------------------------------------------------------

fn stack_analysis(proto_idx: u16, proto: &FunctionProto) -> Result<(), VerifyError> {
    let code_len = proto.code.len();
    if code_len == 0 {
        return Ok(());
    }

    // depths[pc] = known stack depth at entry to instruction pc.
    let mut depths: Vec<Option<usize>> = vec![None; code_len];

    // Worklist: (pc, depth_at_entry)
    let mut worklist: VecDeque<(usize, usize)> = VecDeque::new();

    // Seed with entry: params are in local slots (not on the operand stack).
    // The operand stack starts empty at function entry.
    let entry_depth = 0usize;
    schedule(proto_idx, 0, entry_depth, &mut depths, &mut worklist)?;

    while let Some((pc, d)) = worklist.pop_front() {
        // If this pc already has a different depth recorded, skip (was validated
        // when we scheduled it).
        if depths[pc] != Some(d) {
            continue;
        }

        let instr = &proto.code[pc];

        match instr {
            // --- Terminal instructions ---
            Instruction::Ret(n) => {
                let expected = *n as usize;
                if d != expected {
                    return Err(VerifyError::RetStackMismatch {
                        proto: proto_idx,
                        pc,
                        expected,
                        got: d,
                    });
                }
                // No successors.
            }
            Instruction::Error => {
                // Consumes 1 value, terminal.
                if d < 1 {
                    return Err(VerifyError::StackUnderflow {
                        proto: proto_idx,
                        pc,
                    });
                }
                // No successors.
            }

            // --- Unconditional jump ---
            Instruction::Jmp(off) => {
                // No stack delta; jump is the only successor.
                let target = jump_target(pc, *off, code_len).unwrap(); // validated structurally
                schedule(proto_idx, target, d, &mut depths, &mut worklist)?;
                // Fall-through is dead — do not schedule pc+1.
            }

            // --- Conditional jumps (consume condition, branch or fall-through) ---
            Instruction::JmpIf(off) | Instruction::JmpIfNot(off) => {
                if d < 1 {
                    return Err(VerifyError::StackUnderflow {
                        proto: proto_idx,
                        pc,
                    });
                }
                let d_out = d - 1;
                let target = jump_target(pc, *off, code_len).unwrap();
                // Both paths have depth d_out.
                schedule(proto_idx, target, d_out, &mut depths, &mut worklist)?;
                schedule(proto_idx, pc + 1, d_out, &mut depths, &mut worklist)?;
            }

            // --- Short-circuit And / Or (net 0 on both paths) ---
            Instruction::And(off) | Instruction::Or(off) => {
                if d < 1 {
                    return Err(VerifyError::StackUnderflow {
                        proto: proto_idx,
                        pc,
                    });
                }
                let target = jump_target(pc, *off, code_len).unwrap();
                // Both paths keep the value (net 0).
                schedule(proto_idx, target, d, &mut depths, &mut worklist)?;
                schedule(proto_idx, pc + 1, d, &mut depths, &mut worklist)?;
            }

            // --- Iterator init: fall-through net 0 (table→handle), jump net -1 ---
            Instruction::IterInitSorted(off) | Instruction::IterInitArray(off) => {
                if d < 1 {
                    return Err(VerifyError::StackUnderflow {
                        proto: proto_idx,
                        pc,
                    });
                }
                let target = jump_target(pc, *off, code_len).unwrap();
                // Skip path: table popped, nothing pushed.
                let d_skip = d - 1;
                schedule(proto_idx, target, d_skip, &mut depths, &mut worklist)?;
                // Fall-through: table → handle (net 0).
                schedule(proto_idx, pc + 1, d, &mut depths, &mut worklist)?;
            }

            // --- Iterator next: fall-through +2 (push key+value), jump -1 (pop handle) ---
            Instruction::IterNext(off) => {
                if d < 1 {
                    return Err(VerifyError::StackUnderflow {
                        proto: proto_idx,
                        pc,
                    });
                }
                let target = jump_target(pc, *off, code_len).unwrap();
                // Exhausted path: handle popped.
                let d_done = d - 1;
                schedule(proto_idx, target, d_done, &mut depths, &mut worklist)?;
                // Hit path: key + value pushed on top of handle.
                let d_hit = d + 2;
                if d_hit > MAX_STACK_DEPTH {
                    return Err(VerifyError::StackOverflow {
                        proto: proto_idx,
                        pc,
                        depth: d_hit,
                    });
                }
                schedule(proto_idx, pc + 1, d_hit, &mut depths, &mut worklist)?;
            }

            // --- All other (non-branching) instructions ---
            instr => {
                let (min_depth, delta) = stack_effect(instr);
                if d < min_depth {
                    return Err(VerifyError::StackUnderflow {
                        proto: proto_idx,
                        pc,
                    });
                }
                let d_out = apply_delta(proto_idx, pc, d, delta)?;
                if pc + 1 <= code_len {
                    // Only schedule fall-through if there is a next instruction.
                    if pc + 1 < code_len {
                        schedule(proto_idx, pc + 1, d_out, &mut depths, &mut worklist)?;
                    }
                    // If pc+1 == code_len the instruction falls off the end; that's
                    // only valid if d_out == 0 (implicit Ret(0)), but we leave that
                    // to the compiler to ensure — the spec only mandates Ret checks.
                }
            }
        }
    }

    Ok(())
}

/// Schedule a pc with a given depth. Validates merge consistency.
fn schedule(
    proto_idx: u16,
    pc: usize,
    depth: usize,
    depths: &mut Vec<Option<usize>>,
    worklist: &mut VecDeque<(usize, usize)>,
) -> Result<(), VerifyError> {
    match depths[pc] {
        None => {
            depths[pc] = Some(depth);
            worklist.push_back((pc, depth));
        }
        Some(existing) => {
            if existing != depth {
                return Err(VerifyError::StackDepthMismatch {
                    proto: proto_idx,
                    pc,
                    expected: existing,
                    got: depth,
                });
            }
            // Already scheduled with the same depth — no need to re-add.
        }
    }
    Ok(())
}

/// Apply a signed stack delta to depth `d`, checking underflow and overflow.
fn apply_delta(proto_idx: u16, pc: usize, d: usize, delta: isize) -> Result<usize, VerifyError> {
    let new_d = d as isize + delta;
    if new_d < 0 {
        return Err(VerifyError::StackUnderflow {
            proto: proto_idx,
            pc,
        });
    }
    let new_d = new_d as usize;
    if new_d > MAX_STACK_DEPTH {
        return Err(VerifyError::StackOverflow {
            proto: proto_idx,
            pc,
            depth: new_d,
        });
    }
    Ok(new_d)
}

/// Returns `(min_stack_depth_required, net_stack_delta)` for non-branching instructions.
/// The minimum required depth is checked *before* the delta is applied so that
/// instructions which pop multiple values before pushing correctly detect underflow
/// even when the net delta is non-negative.
///
/// Branching instructions are handled explicitly in stack_analysis.
fn stack_effect(instr: &Instruction) -> (usize, isize) {
    match instr {
        Instruction::Nop => (0, 0),
        Instruction::PushK(_) => (0, 1),
        Instruction::PushNil => (0, 1),
        Instruction::PushTrue => (0, 1),
        Instruction::PushFalse => (0, 1),
        Instruction::Pop => (1, -1),
        Instruction::Dup => (1, 1),
        Instruction::LoadLocal(_) => (0, 1),
        Instruction::StoreLocal(_) => (1, -1),
        Instruction::LoadUp(_) => (0, 1),
        Instruction::StoreUp(_) => (1, -1),
        Instruction::NewTable => (0, 1),
        // GetTable: pops table + key (needs 2), pushes value → net -1
        Instruction::GetTable => (2, -1),
        // SetTable: pops table + key + value (needs 3) → net -3
        Instruction::SetTable => (3, -3),
        // GetField: pops table (needs 1), pushes value → net 0
        Instruction::GetField(_) => (1, 0),
        // SetField: pops table + value (needs 2) → net -2
        Instruction::SetField(_) => (2, -2),
        // Binary ops: pop 2, push 1 → net -1  (require 2 operands)
        Instruction::Add
        | Instruction::Sub
        | Instruction::Mul
        | Instruction::IDiv
        | Instruction::Mod
        | Instruction::Eq
        | Instruction::Ne
        | Instruction::Lt
        | Instruction::Le
        | Instruction::Gt
        | Instruction::Ge => (2, -1),
        // Unary ops: pop 1, push 1 → net 0
        Instruction::Neg | Instruction::Not | Instruction::Len => (1, 0),
        // Concat(n): n values → 1 string (requires n slots)
        Instruction::Concat(n) => (*n as usize, -(*n as isize - 1)),
        // Call(argc): pops func + argc args (needs argc+1), pushes 1 result → net -argc
        Instruction::Call(argc) => (*argc as usize + 1, -(*argc as isize)),
        // PCall(argc): pops func + argc args (needs argc+1), pushes ok + result → net 1-argc
        Instruction::PCall(argc) => (*argc as usize + 1, 1 - *argc as isize),
        // Closure: pushes function value
        Instruction::Closure(_) => (0, 1),
        // ToolCall: pops name + args_table (needs 2), pushes result → net -1
        Instruction::ToolCall => (2, -1),
        // Log: pops 1 value
        Instruction::Log => (1, -1),
        // Branching instructions handled explicitly — should not be called here.
        Instruction::Ret(_)
        | Instruction::Error
        | Instruction::Jmp(_)
        | Instruction::JmpIf(_)
        | Instruction::JmpIfNot(_)
        | Instruction::And(_)
        | Instruction::Or(_)
        | Instruction::IterInitSorted(_)
        | Instruction::IterInitArray(_)
        | Instruction::IterNext(_) => (0, 0), // unreachable in practice
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::proto::{CompiledProgram, Constant, FunctionProto, Instruction};

    fn make_program(protos: Vec<FunctionProto>) -> CompiledProgram {
        CompiledProgram {
            prototypes: protos,
            program_hash: [0u8; 32],
        }
    }

    fn simple_proto(code: Vec<Instruction>) -> FunctionProto {
        let lines = vec![1u32; code.len()];
        FunctionProto {
            code,
            constants: vec![],
            local_count: 0,
            upvalue_count: 0,
            param_count: 0,
            lines,
            max_stack: 0,
            upvalues: vec![],
        }
    }

    fn proto_with_consts(code: Vec<Instruction>, constants: Vec<Constant>) -> FunctionProto {
        let lines = vec![1u32; code.len()];
        FunctionProto {
            code,
            constants,
            local_count: 0,
            upvalue_count: 0,
            param_count: 0,
            lines,
            max_stack: 0,
            upvalues: vec![],
        }
    }

    // -----------------------------------------------------------------------
    // Structural checks
    // -----------------------------------------------------------------------

    #[test]
    fn verify_ok_empty_function() {
        // Single Ret(0) with empty stack.
        let p = make_program(vec![simple_proto(vec![Instruction::Ret(0)])]);
        assert_eq!(verify(&p), Ok(()));
    }

    #[test]
    fn verify_ok_simple_add() {
        // PushK(0), PushK(0), Add, Ret(1)
        let p = make_program(vec![proto_with_consts(
            vec![
                Instruction::PushK(0),
                Instruction::PushK(0),
                Instruction::Add,
                Instruction::Ret(1),
            ],
            vec![Constant::Integer(1)],
        )]);
        assert_eq!(verify(&p), Ok(()));
    }

    #[test]
    fn const_index_oob() {
        // PushK(99) but pool has 1 entry.
        let p = make_program(vec![proto_with_consts(
            vec![Instruction::PushK(99), Instruction::Ret(1)],
            vec![Constant::Integer(0)],
        )]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::ConstantIndexOob { index: 99, .. })
        ));
    }

    #[test]
    fn proto_index_oob() {
        // Closure(5) but only 1 prototype.
        let p = make_program(vec![simple_proto(vec![
            Instruction::Closure(5),
            Instruction::Ret(1),
        ])]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::ProtoIndexOob { index: 5, .. })
        ));
    }

    #[test]
    fn upvalue_index_oob() {
        let lines = vec![1u32; 2];
        let proto = FunctionProto {
            code: vec![Instruction::LoadUp(3), Instruction::Ret(1)],
            constants: vec![],
            local_count: 0,
            upvalue_count: 2, // only 0 and 1 are valid
            param_count: 0,
            lines,
            max_stack: 0,
            upvalues: vec![],
        };
        let p = make_program(vec![proto]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::UpvalueIndexOob { index: 3, .. })
        ));
    }

    #[test]
    fn jump_forward_out_of_range() {
        // Jmp(+9999) in a 2-instruction function.
        let p = make_program(vec![simple_proto(vec![
            Instruction::Jmp(9999),
            Instruction::Ret(0),
        ])]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::JumpOutOfRange { .. })
        ));
    }

    #[test]
    fn jump_backward_out_of_range() {
        let p = make_program(vec![simple_proto(vec![
            Instruction::Jmp(-9999),
            Instruction::Ret(0),
        ])]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::JumpOutOfRange { .. })
        ));
    }

    #[test]
    fn getfield_const_oob() {
        let p = make_program(vec![proto_with_consts(
            vec![
                Instruction::PushNil,
                Instruction::GetField(100),
                Instruction::Ret(1),
            ],
            vec![Constant::Integer(0)],
        )]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::ConstantIndexOob { index: 100, .. })
        ));
    }

    #[test]
    fn setfield_const_oob() {
        let p = make_program(vec![proto_with_consts(
            vec![
                Instruction::PushNil,
                Instruction::PushNil,
                Instruction::SetField(100),
                Instruction::Ret(0),
            ],
            vec![Constant::Integer(0)],
        )]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::ConstantIndexOob { index: 100, .. })
        ));
    }

    #[test]
    fn and_jump_oob() {
        // And(9999) — jump target is way out of range.
        let p = make_program(vec![proto_with_consts(
            vec![
                Instruction::PushTrue,
                Instruction::And(9999),
                Instruction::Ret(1),
            ],
            vec![],
        )]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::JumpOutOfRange { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Stack depth / abstract interpretation
    // -----------------------------------------------------------------------

    #[test]
    fn stack_underflow_pop_empty() {
        // Pop on empty stack.
        let p = make_program(vec![simple_proto(vec![
            Instruction::Pop,
            Instruction::Ret(0),
        ])]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::StackUnderflow { .. })
        ));
    }

    #[test]
    fn stack_underflow_arithmetic() {
        // Add with only 1 value.
        let p = make_program(vec![proto_with_consts(
            vec![Instruction::PushK(0), Instruction::Add, Instruction::Ret(1)],
            vec![Constant::Integer(1)],
        )]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::StackUnderflow { .. })
        ));
    }

    #[test]
    fn stack_overflow() {
        // Push 257 values (exceed MAX_STACK_DEPTH=256).
        let mut code: Vec<Instruction> = (0..257).map(|_| Instruction::PushNil).collect();
        code.push(Instruction::Ret(0)); // won't reach here but structurally needed
        let p = make_program(vec![simple_proto(code)]);
        assert!(matches!(verify(&p), Err(VerifyError::StackOverflow { .. })));
    }

    #[test]
    fn ret_count_mismatch() {
        // Ret(1) but stack is empty.
        let p = make_program(vec![simple_proto(vec![Instruction::Ret(1)])]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::RetStackMismatch { .. })
        ));
    }

    #[test]
    fn ret_too_many() {
        // Ret(0) but stack has 1 value.
        let p = make_program(vec![proto_with_consts(
            vec![Instruction::PushK(0), Instruction::Ret(0)],
            vec![Constant::Integer(0)],
        )]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::RetStackMismatch { .. })
        ));
    }

    #[test]
    fn branch_depth_mismatch() {
        // Build: PushTrue, JmpIfNot(+1), PushNil, [merge point] Ret(0)
        // if-branch: depth at merge = 0
        // else (fall-through after JmpIfNot then skip PushNil via jump):
        //   Actually let's construct it manually:
        //   0: PushNil       depth 0→1
        //   1: JmpIfNot(+1)  depth 1→0; fall-through to 2, jump to 3
        //   2: PushNil       depth 0→1  (only on fall-through)
        //   3: Ret(0)        depth must be 0 on jump path, but 1 on fall-through → mismatch
        let p = make_program(vec![simple_proto(vec![
            Instruction::PushNil,     // 0: depth 0→1
            Instruction::JmpIfNot(1), // 1: depth 1, fall→2 @0, jump→3 @0
            Instruction::PushNil,     // 2: depth 0→1
            Instruction::Ret(0), // 3: reachable with depth 1 (fall-through) and 0 (jump) → mismatch
        ])]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::StackDepthMismatch { .. })
        ));
    }

    #[test]
    fn branch_both_paths_ok() {
        // Symmetric if/else both produce depth 1 at merge.
        // 0: PushNil
        // 1: JmpIfNot(+2)    fall→2, jump→4
        // 2: PushNil         depth 0→1
        // 3: Jmp(+1)         jump to 5
        // 4: PushNil         depth 0→1  (else branch)
        // 5: Ret(1)          depth 1 on both paths ✓
        let p = make_program(vec![simple_proto(vec![
            Instruction::PushNil,     // 0
            Instruction::JmpIfNot(2), // 1: fall→2@0, jump→4@0
            Instruction::PushNil,     // 2: 0→1
            Instruction::Jmp(1),      // 3: jump→5@1
            Instruction::PushNil,     // 4: 0→1
            Instruction::Ret(1),      // 5: depth 1 ✓
        ])]);
        assert_eq!(verify(&p), Ok(()));
    }

    #[test]
    fn jmpif_consumes_value() {
        // 0: PushNil        depth 0→1
        // 1: JmpIf(0)       depth 1; fall→2@0, jump→2@0 (both consume condition)
        // 2: Ret(0)         depth 0 ✓
        let p = make_program(vec![simple_proto(vec![
            Instruction::PushNil,
            Instruction::JmpIf(0), // offset 0: target = pc(1)+1+0 = 2
            Instruction::Ret(0),
        ])]);
        assert_eq!(verify(&p), Ok(()));
    }

    #[test]
    fn back_edge_depth_consistent() {
        // Minimal while(true) loop that exits immediately:
        // 0: PushTrue       depth 0→1
        // 1: JmpIfNot(+1)   fall→2@0, jump→3@0
        // 2: Jmp(-3)        jump to pc(2)+1-3 = 0 @0 — but 0 already has depth 0? no, entry is 0.
        //
        // Actually let's use a simpler back-edge:
        // 0: Jmp(0)         jump to pc(0)+1+0 = 1... that's not a back edge.
        //
        // Clean back-edge loop:
        // 0: PushTrue       → depth 1
        // 1: JmpIfNot(1)    → fall@2 d=0, jump@3 d=0
        // 2: Jmp(-3)        → jump to pc(2)+1-3 = 0  @d=0  (back edge to pc 0, which has d=0 ✓)
        // 3: Ret(0)         depth 0 ✓
        let p = make_program(vec![simple_proto(vec![
            Instruction::PushTrue,    // 0
            Instruction::JmpIfNot(1), // 1: fall→2@0, jump→3@0
            Instruction::Jmp(-3),     // 2: → pc 0 @ depth 0 ✓
            Instruction::Ret(0),      // 3
        ])]);
        assert_eq!(verify(&p), Ok(()));
    }

    #[test]
    fn back_edge_depth_mismatch() {
        // Loop body leaves an extra value on the stack.
        // 0: PushTrue       → depth 1
        // 1: JmpIfNot(2)    fall→2@0, jump→4@0
        // 2: PushNil        → depth 1  (extra value, not consumed)
        // 3: Jmp(-4)        → pc 0 @ depth 1, but pc 0 expects depth 0 → mismatch
        // 4: Ret(0)
        let p = make_program(vec![simple_proto(vec![
            Instruction::PushTrue,    // 0: d=0→1
            Instruction::JmpIfNot(2), // 1: fall→2@0, jump→4@0
            Instruction::PushNil,     // 2: d=0→1
            Instruction::Jmp(-4),     // 3: → pc 0 @ d=1 (expected 0) → mismatch
            Instruction::Ret(0),      // 4
        ])]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::StackDepthMismatch { .. })
        ));
    }

    #[test]
    fn call_delta() {
        // Call(2): push func + 2 args → depth 3, Call(2) → depth 1 (net -2).
        // Then Ret(1).
        let p = make_program(vec![proto_with_consts(
            vec![
                Instruction::PushK(0), // func
                Instruction::PushK(0), // arg1
                Instruction::PushK(0), // arg2
                Instruction::Call(2),  // depth 3 → 1
                Instruction::Ret(1),
            ],
            vec![Constant::Integer(0)],
        )]);
        assert_eq!(verify(&p), Ok(()));
    }

    #[test]
    fn pcall_delta() {
        // PCall(1): push func + 1 arg → depth 2, PCall(1) → depth 2 (net 1-1=0... wait)
        // PCall(argc=1): pops func+1=2, pushes 2 (ok+result). Net = 2-2 = 0.
        // Stack: [func, arg] → [ok, result]  depth stays at 2.
        // Ret(2) would need 2 values; but spec says Ret(0) or Ret(1) only. Use Ret(1) after Pop.
        // Let's just check: PushNil (func), PushNil (arg), PCall(1), depth = 2, Ret...
        // PCall(argc=1): net = 1 - 1 = 0, so depth stays at 2. Pop to get 1, Ret(1).
        let p = make_program(vec![simple_proto(vec![
            Instruction::PushNil,  // func  depth 0→1
            Instruction::PushNil,  // arg   depth 1→2
            Instruction::PCall(1), // depth 2→2 (net 0: pops 2, pushes 2)
            Instruction::Pop,      // pop one of the two results → depth 1
            Instruction::Ret(1),   // depth 1 ✓
        ])]);
        assert_eq!(verify(&p), Ok(()));
    }

    // -----------------------------------------------------------------------
    // Iterator handle slot tracking
    // -----------------------------------------------------------------------

    /// Build a complete pairs_sorted loop that verifies cleanly.
    /// Shape (from spec §7.4):
    ///   ITER_INIT_SORTED  +N   (jump to end if empty)
    ///   ITER_NEXT         +M   (jump past end when done)
    ///   [loop body]
    ///   POP               (pop v)
    ///   POP               (pop k)
    ///   JMP               -K   (back to ITER_NEXT)
    ///   [end of loop]
    ///
    /// Concrete encoding with pc indices:
    ///   0: PushNil                    push table placeholder
    ///   1: IterInitSorted(+4)         fall→2@1, jump→6@0
    ///   2: IterNext(+3)               fall→3@3, jump→6@0
    ///   3: Pop                        d=3→2
    ///   4: Pop                        d=2→1
    ///   5: Jmp(-4)                    → pc 2 @ d=1 ✓ (matches entry to ITER_NEXT)
    ///   6: Ret(0)                     d=0 ✓
    #[test]
    fn iter_init_sorted_ok() {
        let p = make_program(vec![simple_proto(vec![
            Instruction::PushNil,           // 0: d=0→1
            Instruction::IterInitSorted(4), // 1: fall→2@1, jump→6@0
            Instruction::IterNext(3),       // 2: fall→3@3, jump→6@0
            Instruction::Pop,               // 3: d=3→2
            Instruction::Pop,               // 4: d=2→1
            Instruction::Jmp(-4),           // 5: → pc(5)+1-4 = 2 @ d=1 ✓
            Instruction::Ret(0),            // 6: d=0 ✓
        ])]);
        assert_eq!(verify(&p), Ok(()));
    }

    #[test]
    fn iter_init_array_ok() {
        // Same shape with IterInitArray.
        let p = make_program(vec![simple_proto(vec![
            Instruction::PushNil,          // 0: d=0→1
            Instruction::IterInitArray(4), // 1: fall→2@1, jump→6@0
            Instruction::IterNext(3),      // 2: fall→3@3, jump→6@0
            Instruction::Pop,              // 3: d=3→2
            Instruction::Pop,              // 4: d=2→1
            Instruction::Jmp(-4),          // 5: → pc 2 @ d=1 ✓
            Instruction::Ret(0),           // 6: d=0 ✓
        ])]);
        assert_eq!(verify(&p), Ok(()));
    }

    #[test]
    fn iter_empty_table_jump() {
        // When the table is empty, IterInitSorted jumps directly to end.
        // The jump target (pc 2 = Ret(0)) must receive depth 0 (table was popped, no handle).
        // 0: PushNil                d=0→1
        // 1: IterInitSorted(0)      fall→2@1, jump→2@0
        // 2: Ret(0)                 needs depth 0; but also receives d=1 from fall-through → mismatch
        //
        // To make it clean, we need the end-of-loop label to be reached only via the jump:
        // 0: PushNil                d=0→1
        // 1: IterInitSorted(1)      fall→2@1, jump→3@0
        // 2: Jmp(0)                 → pc 3 @ d=1 — but 3 will have d=0 from jump → mismatch
        //
        // The correct way: the empty-table skip path depth (d-1=0) must agree with
        // wherever it jumps. Let's test that the skip path produces depth 0:
        // 0: PushNil
        // 1: IterInitSorted(+4)  → skip target = pc6 @ d=0
        // 2: IterNext(+3)        → done target = pc6 @ d=0 (already set) ✓
        // 3: Pop  4: Pop  5: Jmp(-4)
        // 6: Ret(0)              d=0 ✓
        // This is the same as iter_init_sorted_ok — already verified. For explicit
        // empty-skip test, verify the skip-path-only scenario with only one instruction:
        // 0: PushNil               d=0→1
        // 1: IterInitSorted(0)     fall→2@1, jump→2@0 → MISMATCH (1 vs 0)
        let p = make_program(vec![simple_proto(vec![
            Instruction::PushNil,
            Instruction::IterInitSorted(0), // both paths go to pc 2, but at depths 1 and 0
            Instruction::Ret(0),
        ])]);
        // The two paths (fall: d=1, jump: d=0) disagree at pc 2 → StackDepthMismatch.
        assert!(matches!(
            verify(&p),
            Err(VerifyError::StackDepthMismatch { .. })
        ));
    }

    #[test]
    fn iter_next_hit_depth() {
        // After ITER_NEXT hit path, key+value are on top → depth increases by 2.
        // 0: PushNil               d=0→1  (table)
        // 1: IterInitSorted(3)     fall→2@1, jump→5@0
        // 2: IterNext(2)           fall→3@3, jump→5@0
        // 3: Pop  → d=2
        // 4: Pop  → d=1
        //    Jmp back to 2 would close the loop, but here we just check depth at entry to body (3):
        //    we must hit Ret at depth > 0 after the loop. Use a simpler structure:
        // 0: PushNil
        // 1: IterInitSorted(4)     fall→2@1, jump→6@0
        // 2: IterNext(3)           fall→3@3, jump→6@0
        // 3: Pop                   d=3→2
        // 4: Pop                   d=2→1
        // 5: Jmp(-4)               → pc 2 @ d=1 ✓
        // 6: Ret(0)
        // (Same as iter_init_sorted_ok — which already tests this.) This test is a
        // more explicit check that the hit path gives d+2:
        // Build a malformed proto that after ITER_NEXT hit tries to Ret(1) with d=3 — that's a
        // RetStackMismatch, which confirms the hit path gives depth 3.
        let p = make_program(vec![simple_proto(vec![
            Instruction::PushNil,           // 0: d=0→1
            Instruction::IterInitSorted(3), // 1: fall→2@1, jump→5@0
            Instruction::IterNext(2),       // 2: fall→3@3, jump→5@0
            Instruction::Ret(1),            // 3: d=3, expected 1 → RetStackMismatch
            Instruction::Ret(0),            // 4: (unreachable from init-hit path)
            Instruction::Ret(0),            // 5: d=0 ✓
        ])]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::RetStackMismatch { .. })
        ));
    }

    #[test]
    fn iter_next_done_depth() {
        // The done path of ITER_NEXT pops the handle → depth = pre-init depth.
        // Pre-init depth = 0, so after done jump target must have depth 0.
        // iter_init_sorted_ok tests this cleanly (Ret(0) at end with d=0).
        // Here we verify that a Ret(1) at the done target correctly fails:
        // 0: PushNil               d=0→1  (table)
        // 1: IterInitSorted(2)     fall→2@1, jump→4@0
        // 2: IterNext(1)           fall→3@3, jump→4@0
        // 3: Jmp(-2)               → pc 2 @ d=3? No, that's wrong.
        //
        // Let's use a valid loop structure but put Ret(1) at the done target:
        // 0: PushNil               d=0→1
        // 1: IterInitSorted(4)     fall→2@1, jump→6@0
        // 2: IterNext(3)           fall→3@3, jump→6@0
        // 3: Pop  4: Pop  5: Jmp(-4)
        // 6: Ret(1)               d=0 but expected 1 → RetStackMismatch
        let p = make_program(vec![simple_proto(vec![
            Instruction::PushNil,           // 0
            Instruction::IterInitSorted(4), // 1: fall→2@1, jump→6@0
            Instruction::IterNext(3),       // 2: fall→3@3, jump→6@0
            Instruction::Pop,               // 3
            Instruction::Pop,               // 4
            Instruction::Jmp(-4),           // 5: → pc 2 @ d=1
            Instruction::Ret(1),            // 6: d=0 but Ret(1) expected 1 → mismatch
        ])]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::RetStackMismatch { .. })
        ));
    }

    #[test]
    fn iter_missing_pops() {
        // Loop body forgets to POP key+value before JMP back → depth mismatch at ITER_NEXT.
        // 0: PushNil               d=0→1
        // 1: IterInitSorted(3)     fall→2@1, jump→5@0
        // 2: IterNext(2)           fall→3@3, jump→5@0
        //    [body: no pops]
        // 3: Jmp(-2)               → pc 2 @ d=3  (expected d=1) → StackDepthMismatch
        // 4: Ret(0) (unreachable from loop body but reachable from... actually it's dead)
        // 5: Ret(0)                d=0 ✓
        let p = make_program(vec![simple_proto(vec![
            Instruction::PushNil,           // 0: d=0→1
            Instruction::IterInitSorted(3), // 1: fall→2@1, jump→5@0
            Instruction::IterNext(2),       // 2: fall→3@3, jump→5@0
            Instruction::Jmp(-2),           // 3: → pc(3)+1-2=2 @ d=3 (expected 1) → mismatch
            Instruction::Ret(0),            // 4: dead
            Instruction::Ret(0),            // 5: d=0 ✓
        ])]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::StackDepthMismatch { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Prototype DAG check
    // -----------------------------------------------------------------------

    #[test]
    fn proto_dag_ok() {
        // Proto 0 (top-level) references proto 1 (inner function) — valid DAG.
        let inner = simple_proto(vec![Instruction::Ret(0)]);
        let outer = proto_with_consts(
            vec![
                Instruction::Closure(1),
                Instruction::Pop,
                Instruction::Ret(0),
            ],
            vec![Constant::Proto(1)],
        );
        let p = make_program(vec![outer, inner]);
        assert_eq!(verify(&p), Ok(()));
    }

    #[test]
    fn proto_dag_cycle() {
        // Proto 0 has Constant::Proto(0) → self-reference → cycle.
        let proto = proto_with_consts(
            vec![
                Instruction::Closure(0),
                Instruction::Pop,
                Instruction::Ret(0),
            ],
            vec![Constant::Proto(0)],
        );
        let p = make_program(vec![proto]);
        assert!(matches!(
            verify(&p),
            Err(VerifyError::PrototypeCycle { .. })
        ));
    }
}
