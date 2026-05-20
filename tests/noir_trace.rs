use luai::types::value::LuaValue;
use luai::{
    bytecode::verify,
    compiler::compile,
    noir::opcodes::{JMP_IF_NOT, RET},
    parser::parse,
    vm::engine::{NoopHost, Vm, VmConfig},
};

fn make_vm(record_trace: bool) -> Vm<NoopHost> {
    Vm::new(
        VmConfig {
            record_trace,
            ..VmConfig::default()
        },
        NoopHost,
    )
}

fn compile_program(src: &str) -> luai::compiler::proto::CompiledProgram {
    let ast = parse(src).expect("parse");
    let program = compile(&ast).expect("compile");
    verify(&program).expect("verify");
    program
}

#[test]
fn trace_length_matches_instruction_count() {
    // "return 1 + 2" dispatches exactly 4 instructions: PushK, PushK, Add, Ret.
    // The compiler appends an unreachable fallback instruction after an explicit
    // return, so code.len() == 5; only the 4 reachable ones produce trace steps.
    let program = compile_program("return 1 + 2");
    let mut vm = make_vm(true);
    let output = vm.execute(&program, LuaValue::Nil).unwrap();
    assert_eq!(output.trace.len(), 4);
}

#[test]
fn trace_pc_sequential_for_linear_program() {
    let program = compile_program("return 1 + 2");

    let mut vm = make_vm(true);
    let output = vm.execute(&program, LuaValue::Nil).unwrap();

    for (i, step) in output.trace.iter().enumerate() {
        assert_eq!(
            step.pc, i as u32,
            "step {i} has pc={} but expected {i}",
            step.pc
        );
    }
}

#[test]
fn trace_jump_produces_correct_next_pc() {
    // JmpIfNot is taken because the condition is false → next_pc jumps forward.
    let program = compile_program("if false then return 99 end return 1");

    let mut vm = make_vm(true);
    let output = vm.execute(&program, LuaValue::Nil).unwrap();

    let jump_step = output
        .trace
        .iter()
        .find(|s| s.opcode == JMP_IF_NOT)
        .expect("expected a JmpIfNot in the trace");

    // The branch is taken (false condition), so next_pc must be greater than pc+1.
    assert!(
        jump_step.next_pc > jump_step.pc + 1,
        "expected taken branch: next_pc={} should be > pc+1={}",
        jump_step.next_pc,
        jump_step.pc + 1
    );
}

#[test]
fn trace_is_empty_without_flag() {
    let program = compile_program("return 1 + 2");

    let mut vm = make_vm(false);
    let output = vm.execute(&program, LuaValue::Nil).unwrap();

    assert!(output.trace.is_empty());
}

#[test]
fn trace_is_deterministic() {
    let program = compile_program("return 1 + 2 * 3");

    let mut vm1 = make_vm(true);
    let out1 = vm1.execute(&program, LuaValue::Nil).unwrap();

    let mut vm2 = make_vm(true);
    let out2 = vm2.execute(&program, LuaValue::Nil).unwrap();

    assert_eq!(out1.trace.len(), out2.trace.len());
    for (a, b) in out1.trace.iter().zip(out2.trace.iter()) {
        assert_eq!(a, b);
    }
}

#[test]
fn trace_stack_top_coerces_bool_to_int() {
    // PushTrue; PushFalse — the step just before a Ret should have stack_top=0 (false)
    // or 1 (true). We run "return true" and look at the Ret step's stack_top.
    let program = compile_program("return true");

    let mut vm = make_vm(true);
    let output = vm.execute(&program, LuaValue::Nil).unwrap();

    let ret_step = output
        .trace
        .iter()
        .find(|s| s.opcode == RET)
        .expect("expected Ret in trace");

    // Just before Ret, the stack top is `true` → coerced to 1.
    assert_eq!(ret_step.stack_top, 1);
}
