#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Instruction set for the Lua VM bytecode.
///
/// Jump offsets (`i16`) are relative to the instruction *after* the jump,
/// i.e. target = pc + 1 + offset.  Negative offsets are back-edges.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Instruction {
    Nop,
    PushK(u16), // push constant[idx]
    PushNil,
    PushTrue,
    PushFalse,
    Pop,
    Dup,
    LoadLocal(u8),
    StoreLocal(u8),
    LoadUp(u8),
    StoreUp(u8),
    NewTable,
    GetTable,
    SetTable,
    GetField(u16), // key = constant[idx] (must be string)
    SetField(u16), // key = constant[idx] (must be string)
    Add,
    Sub,
    Mul,
    IDiv,
    Mod,
    Neg,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Not,
    And(i16),   // short-circuit offset
    Or(i16),    // short-circuit offset
    Concat(u8), // n values
    Len,
    Jmp(i16),
    JmpIf(i16),
    JmpIfNot(i16),
    Call(u8),     // argc
    Ret(u8),      // n return values (0 or 1)
    Closure(u16), // prototype index
    ToolCall,
    PCall(u8), // argc
    Log,
    Error,
    IterInitSorted(i16), // jump offset if empty
    IterInitArray(i16),  // jump offset if empty
    IterNext(i16),       // jump offset when exhausted
}

/// Constant pool entry.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Constant {
    Nil,
    Boolean(bool),
    Integer(i64),
    String(Vec<u8>),
    Proto(u16), // index into CompiledProgram::prototypes
}

/// A compiled function prototype (one per function/closure/top-level chunk).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FunctionProto {
    /// Flat instruction list.
    pub code: Vec<Instruction>,
    /// Constant pool — indexed by PushK / GetField / SetField operands.
    pub constants: Vec<Constant>,
    /// Number of local variable slots (set after compiling the function body).
    pub local_count: u8,
    /// Number of upvalues this closure captures.
    pub upvalue_count: u8,
    /// Number of parameters.
    pub param_count: u8,
    /// Per-instruction source line (parallel to `code`; same length).
    pub lines: Vec<u32>,
    /// Maximum stack depth observed during compilation (for the verifier).
    pub max_stack: u16,
    /// Upvalue descriptors: for each upvalue, where it comes from.
    pub upvalues: Vec<UpvalueDesc>,
}

impl FunctionProto {
    pub fn new(param_count: u8) -> Self {
        FunctionProto {
            code: Vec::new(),
            constants: Vec::new(),
            local_count: 0,
            upvalue_count: 0,
            param_count,
            lines: Vec::new(),
            max_stack: 0,
            upvalues: Vec::new(),
        }
    }
}

/// Describes how a closure captures a variable.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UpvalueDesc {
    /// Capture from the enclosing function's local slot.
    Local(u8),
    /// Capture from the enclosing function's upvalue slot.
    Upvalue(u8),
}

/// The output of the compiler: all function prototypes + a program hash.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CompiledProgram {
    /// Index 0 is always the top-level chunk (implicit function with 0 params).
    pub prototypes: Vec<FunctionProto>,
    /// SHA-256 of the canonical encoding of all prototypes.
    pub program_hash: [u8; 32],
}
