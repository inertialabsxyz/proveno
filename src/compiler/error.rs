#[cfg(not(feature = "std"))]
use alloc::{format, string::String};

/// Errors produced during compilation (AST → bytecode).
#[derive(Debug, PartialEq)]
pub enum CompileError {
    /// `tool` used outside `tool.call(...)`
    ToolAsValue { line: u32 },
    /// Calling a stored reference to `tool.call`
    IndirectToolCall { line: u32 },
    /// `...` used in an expression context
    VariadicNotAllowed { line: u32 },
    /// More than 200 locals in one function
    TooManyLocals { line: u32 },
    /// More than 255 upvalues
    TooManyUpvalues { line: u32 },
    /// More than 65535 constants in one prototype
    TooManyConstants { line: u32 },
    /// More than 65535 prototypes total
    TooManyPrototypes { line: u32 },
    /// `break` outside a loop
    BreakOutsideLoop { line: u32 },
    /// Expression statement that is not a call
    ExprStmtNotCall { line: u32 },
    /// Multi-assign from a non-pcall expression
    MultiReturnNotAllowed { line: u32 },
    /// Bytecode exceeds maximum size
    BytecodeTooLarge { line: u32 },
    /// Generic-for iterator is not pairs_sorted/pairs/ipairs
    GenericForNotIterator { line: u32 },
    /// Unknown global name
    UnknownGlobal { name: String, line: u32 },
}

impl CompileError {
    pub fn code(&self) -> &'static str {
        "ERR_COMPILE"
    }

    pub fn line(&self) -> u32 {
        match self {
            CompileError::ToolAsValue { line } => *line,
            CompileError::IndirectToolCall { line } => *line,
            CompileError::VariadicNotAllowed { line } => *line,
            CompileError::TooManyLocals { line } => *line,
            CompileError::TooManyUpvalues { line } => *line,
            CompileError::TooManyConstants { line } => *line,
            CompileError::TooManyPrototypes { line } => *line,
            CompileError::BreakOutsideLoop { line } => *line,
            CompileError::ExprStmtNotCall { line } => *line,
            CompileError::MultiReturnNotAllowed { line } => *line,
            CompileError::BytecodeTooLarge { line } => *line,
            CompileError::GenericForNotIterator { line } => *line,
            CompileError::UnknownGlobal { line, .. } => *line,
        }
    }

    pub fn message(&self) -> String {
        match self {
            CompileError::ToolAsValue { line } => {
                format!("line {}: `tool` cannot be used as a value", line)
            }
            CompileError::IndirectToolCall { line } => format!(
                "line {}: `tool.call` cannot be stored or passed as a value",
                line
            ),
            CompileError::VariadicNotAllowed { line } => {
                format!("line {}: `...` is not allowed in this context", line)
            }
            CompileError::TooManyLocals { line } => {
                format!("line {}: too many local variables (max 200)", line)
            }
            CompileError::TooManyUpvalues { line } => {
                format!("line {}: too many upvalues (max 255)", line)
            }
            CompileError::TooManyConstants { line } => {
                format!("line {}: too many constants (max 65535)", line)
            }
            CompileError::TooManyPrototypes { line } => {
                format!("line {}: too many function prototypes (max 65535)", line)
            }
            CompileError::BreakOutsideLoop { line } => {
                format!("line {}: `break` outside loop", line)
            }
            CompileError::ExprStmtNotCall { line } => format!(
                "line {}: expression statement must be a function call",
                line
            ),
            CompileError::MultiReturnNotAllowed { line } => format!(
                "line {}: multiple return values only allowed from pcall",
                line
            ),
            CompileError::BytecodeTooLarge { line } => format!("line {}: bytecode too large", line),
            CompileError::GenericForNotIterator { line } => format!(
                "line {}: generic for iterator must be pairs_sorted, pairs, or ipairs",
                line
            ),
            CompileError::UnknownGlobal { name, line } => {
                format!("line {}: unknown global `{}`", line, name)
            }
        }
    }
}
