#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec::Vec};

use super::lexer::Span;

// ---------------------------------------------------------------------------
// Top level
// ---------------------------------------------------------------------------

/// A block is a sequence of statements, optionally ending with a return.
#[derive(Debug, Clone)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub ret: Option<ReturnStmt>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ReturnStmt {
    /// At most one return value in v0.2 (multi-value exceptions handled by the compiler).
    pub value: Option<Expr>,
    pub span: Span,
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Stmt {
    LocalDecl(LocalDecl),
    Assign(Assign),
    If(IfStmt),
    While(WhileStmt),
    NumericFor(NumericFor),
    GenericFor(GenericFor),
    FunctionDecl(FunctionDecl),
    LocalFunctionDecl(LocalFunctionDecl),
    ExprStmt(ExprStmt),
    Break(Span),
    Do(DoBlock),
}

/// `local a, b = expr, expr`
#[derive(Debug, Clone)]
pub struct LocalDecl {
    /// (name, span of name token)
    pub names: Vec<(String, Span)>,
    /// Right-hand side expressions (may differ in count from names).
    pub values: Vec<Expr>,
    pub span: Span,
}

/// `target = expr`
#[derive(Debug, Clone)]
pub struct Assign {
    pub target: AssignTarget,
    pub value: Expr,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum AssignTarget {
    /// Simple variable: `x = ...`
    Name(String, Span),
    /// Table field: `t[k] = ...` or `t.k = ...`
    Index(Box<Expr>, Box<Expr>, Span),
}

/// `if cond then ... elseif ... else ... end`
#[derive(Debug, Clone)]
pub struct IfStmt {
    pub condition: Expr,
    pub then_block: Block,
    pub elseif_clauses: Vec<ElseifClause>,
    pub else_block: Option<Block>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ElseifClause {
    pub condition: Expr,
    pub block: Block,
    pub span: Span,
}

/// `while cond do ... end`
#[derive(Debug, Clone)]
pub struct WhileStmt {
    pub condition: Expr,
    pub block: Block,
    pub span: Span,
}

/// `for var = start, limit [, step] do ... end`
#[derive(Debug, Clone)]
pub struct NumericFor {
    pub var: String,
    pub var_span: Span,
    pub start: Expr,
    pub limit: Expr,
    pub step: Option<Expr>,
    pub block: Block,
    pub span: Span,
}

/// `for k, v in iter(t) do ... end`
#[derive(Debug, Clone)]
pub struct GenericFor {
    /// Loop variables, e.g. `k, v`.
    pub vars: Vec<(String, Span)>,
    /// The expression list after `in` (typically a single iterator call).
    pub iterators: Vec<Expr>,
    pub block: Block,
    pub span: Span,
}

/// `function name.sub.name:method(params) ... end`
#[derive(Debug, Clone)]
pub struct FunctionDecl {
    pub name: FuncName,
    pub func: FuncBody,
    pub span: Span,
}

/// A potentially dot-qualified function name, with optional method suffix.
///
/// `function a.b.c(...)` → `parts = ["a","b","c"]`, `method = None`
/// `function t:m(...)`   → `parts = ["t"]`,          `method = Some("m")`
#[derive(Debug, Clone)]
pub struct FuncName {
    pub parts: Vec<(String, Span)>,
    pub method: Option<(String, Span)>,
}

/// `local function name(params) ... end`
#[derive(Debug, Clone)]
pub struct LocalFunctionDecl {
    pub name: String,
    pub name_span: Span,
    pub func: FuncBody,
    pub span: Span,
}

/// Shared function body: parameter list + block.
#[derive(Debug, Clone)]
pub struct FuncBody {
    pub params: Vec<(String, Span)>,
    pub block: Block,
    pub span: Span,
}

/// A function call used as a statement (value discarded).
#[derive(Debug, Clone)]
pub struct ExprStmt {
    pub expr: Expr,
    pub span: Span,
}

/// `do ... end`
#[derive(Debug, Clone)]
pub struct DoBlock {
    pub block: Block,
    pub span: Span,
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Expr {
    Nil(Span),
    True(Span),
    False(Span),
    Integer(i64, Span),
    StringLit(Vec<u8>, Span),
    /// `...` — accepted syntactically, rejected at compile time.
    Vararg(Span),
    /// Variable reference.
    Name(String, Span),
    TableConstructor(TableConstructor),
    /// `t[k]`
    Index(Box<Expr>, Box<Expr>, Span),
    /// `t.k` (syntactic sugar for `t["k"]`)
    Field(Box<Expr>, String, Span),
    /// `t:method(args)` (syntactic sugar for `t.method(t, args)`)
    MethodCall(MethodCall),
    /// `f(args)`
    Call(Call),
    BinOp(BinOp),
    UnOp(UnOp),
    /// `function(params) ... end`
    FuncDef(Box<FuncBody>, Span),
}

impl Expr {
    /// Return the span of this expression (first token).
    pub fn span(&self) -> Span {
        match self {
            Expr::Nil(s) => *s,
            Expr::True(s) => *s,
            Expr::False(s) => *s,
            Expr::Integer(_, s) => *s,
            Expr::StringLit(_, s) => *s,
            Expr::Vararg(s) => *s,
            Expr::Name(_, s) => *s,
            Expr::TableConstructor(t) => t.span,
            Expr::Index(_, _, s) => *s,
            Expr::Field(_, _, s) => *s,
            Expr::MethodCall(m) => m.span,
            Expr::Call(c) => c.span,
            Expr::BinOp(b) => b.span,
            Expr::UnOp(u) => u.span,
            Expr::FuncDef(_, s) => *s,
        }
    }
}

/// `{ field, ... }`
#[derive(Debug, Clone)]
pub struct TableConstructor {
    pub fields: Vec<TableField>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum TableField {
    /// `[expr] = expr`
    ExplicitKey { key: Expr, value: Expr, span: Span },
    /// `name = expr`
    NamedKey {
        name: String,
        name_span: Span,
        value: Expr,
        span: Span,
    },
    /// `expr` — auto-numbered integer key starting from 1
    Positional { value: Expr, span: Span },
}

/// `f(args)`
#[derive(Debug, Clone)]
pub struct Call {
    pub func: Box<Expr>,
    pub args: Vec<Expr>,
    pub span: Span,
}

/// `obj:method(args)`
#[derive(Debug, Clone)]
pub struct MethodCall {
    pub object: Box<Expr>,
    pub method: String,
    pub method_span: Span,
    pub args: Vec<Expr>,
    pub span: Span,
}

/// Binary expression.
#[derive(Debug, Clone)]
pub struct BinOp {
    pub op: BinOpKind,
    pub left: Box<Expr>,
    pub right: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BinOpKind {
    // Arithmetic
    Add,
    Sub,
    Mul,
    IDiv,
    Mod,
    // String
    Concat,
    // Comparison
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    // Boolean short-circuit
    And,
    Or,
}

/// Unary expression.
#[derive(Debug, Clone)]
pub struct UnOp {
    pub op: UnOpKind,
    pub operand: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UnOpKind {
    Neg, // -
    Not, // not
    Len, // #
}
