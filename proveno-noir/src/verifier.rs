use proveno::{
    HostInterface, Vm, VmConfig,
    compiler::{CompiledProgram, Constant},
    noir::opcodes::*,
    types::value::LuaValue,
};

pub struct NoirVerifier {}

struct NoHost;
impl HostInterface for NoHost {
    fn call_tool(
        &mut self,
        name: &str,
        _args: &proveno::types::table::LuaTable,
    ) -> Result<proveno::types::table::LuaTable, String> {
        Err(format!("tool '{}' not registered", name))
    }
}

// pub const NEW_TABLE: u8 = 11;
// pub const GET_TABLE: u8 = 12;
// pub const SET_TABLE: u8 = 13;
// pub const GET_FIELD: u8 = 14;
// pub const SET_FIELD: u8 = 15;
// pub const ADD: u8 = 16;
// pub const SUB: u8 = 17;
// pub const MUL: u8 = 18;
// pub const IDIV: u8 = 19;
// pub const MOD: u8 = 20;
// pub const NEG: u8 = 21;
// pub const EQ: u8 = 22;
// pub const NE: u8 = 23;
// pub const LT: u8 = 24;
// pub const LE: u8 = 25;
// pub const GT: u8 = 26;
// pub const GE: u8 = 27;
// pub const NOT: u8 = 28;
// pub const AND: u8 = 29;
// pub const OR: u8 = 30;
// pub const CONCAT: u8 = 31;
// pub const LEN: u8 = 32;
// pub const JMP: u8 = 33;
// pub const JMP_IF: u8 = 34;
// pub const JMP_IF_NOT: u8 = 35;
// pub const CALL: u8 = 36;
// pub const RET: u8 = 37;
// pub const CLOSURE: u8 = 38;
// pub const TOOL_CALL: u8 = 39;
// pub const PCALL: u8 = 40;
// pub const LOG: u8 = 41;
// pub const ERROR: u8 = 42;
// pub const ITER_INIT_SORTED: u8 = 43;
// pub const ITER_INIT_ARRAY: u8 = 44;
// pub const ITER_NEXT: u8 = 45;

impl NoirVerifier {
    // Verify each state transition for a trace of a program execution
    pub fn verify(compiled: &CompiledProgram) {
        let config = VmConfig {
            record_trace: true,
            ..VmConfig::default()
        };

        let output = Vm::new(config, NoHost)
            .execute(compiled, LuaValue::Nil)
            .unwrap();

        let trace = output.trace;
        // Constants for chunk
        let constants = compiled.prototypes[0].constants.clone();

        // Trace Step and then dispatch
        for trace in trace.windows(2) {
            let before_dispatch = &trace[0];
            let after_dispatch = &trace[1];
            match before_dispatch.opcode {
                PUSH_K => {
                    let constant = &constants[before_dispatch.operand as usize];
                    match constant {
                        Constant::Integer(integer) => {
                            assert_eq!(after_dispatch.stack_top, *integer);
                        }
                        Constant::Boolean(boolean) => {
                            let b: bool = after_dispatch.stack_top.try_into().unwrap();
                            assert_eq!(b, *boolean);
                        }
                        Constant::String(_) => {
                            assert_eq!(after_dispatch.stack_top, 0);
                        }
                        Constant::Nil => {
                            assert_eq!(after_dispatch.stack_top, 0);
                        }
                        _ => {
                            panic!("not supported");
                        }
                    }
                }
                PUSH_NIL => {
                    assert_eq!(after_dispatch.stack_top, 0);
                }
                PUSH_TRUE => {
                    assert_eq!(after_dispatch.stack_top, 1);
                }
                PUSH_FALSE => {
                    assert_eq!(after_dispatch.stack_top, 0);
                }
                POP => {
                    assert_eq!(after_dispatch.stack_top, before_dispatch.stack_top);
                }
                DUP => {
                    assert_eq!(after_dispatch.stack_top, before_dispatch.stack_top);
                }
                LOAD_LOCAL => {
                    // Read local value and push to stack
                    // TODO - Not available in trace
                }
                STORE_LOCAL => {
                    // Pop stack
                    assert_eq!(after_dispatch.stack_top, before_dispatch.stack_top);
                    // Push to frame's local region
                    // TODO - not available in trace
                }
                LOAD_UP => {
                    // Pushes value that lives in upvalue cell to top of stack, invisible as not in trae
                    // TODO
                }
                STORE_UP => {
                    // Pops value to upvalue cell, invisible as not in trae
                    // TODO
                }
                NEW_TABLE => {}
                GET_TABLE => {}
                SET_TABLE => {}
                GET_FIELD => {}
                SET_FIELD => {}

                _ => {
                    println!("not supported: {:?}", before_dispatch);
                }
            }
        }

        println!("return value = {:?}", output.return_value);
    }
}

#[test]
fn test_basic() {
    let source = "return 42 + 1";
    println!("Source: {}", source);
    let ast = proveno::parser::parse(&source).expect("well formed code");
    let program = proveno::compiler::compile(&ast).expect("compiled code");
    println!("{:?}", program.prototypes);
    NoirVerifier::verify(&program);
}

#[test]
fn test_string() {
    let source = "return 'hello'";

    println!("{:?}", "hello".as_bytes());
    println!("Source: {}", source);
    let ast = proveno::parser::parse(&source).expect("well formed code");
    let program = proveno::compiler::compile(&ast).expect("compiled code");
    println!("{:?}", program.prototypes);
    NoirVerifier::verify(&program);
}

#[test]
fn test_nil() {
    let source = "local x = true\nreturn x";

    println!("Source: {}", source);
    let ast = proveno::parser::parse(&source).expect("well formed code");
    let program = proveno::compiler::compile(&ast).expect("compiled code");
    println!("{:?}", program.prototypes);
    NoirVerifier::verify(&program);
}

#[test]
fn test_pop() {
    let source = "print('hi')\nreturn 0";

    println!("Source: {}", source);
    let ast = proveno::parser::parse(&source).expect("well formed code");
    let program = proveno::compiler::compile(&ast).expect("compiled code");
    println!("{:?}", program.prototypes);
    NoirVerifier::verify(&program);
}

#[test]
fn test_local() {
    let source = "local x = 1\nlocal y = 2\nx = y";

    println!("Source: {}", source);
    let ast = proveno::parser::parse(&source).expect("well formed code");
    let program = proveno::compiler::compile(&ast).expect("compiled code");
    println!("{:?}", program.prototypes);
    NoirVerifier::verify(&program);
}
