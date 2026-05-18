#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

pub mod ast;
pub mod lexer;

use ast::*;
use lexer::{ParseError, Span, SpannedToken, Token};

pub use lexer::ParseError as Error;

/// Parse a Lua-subset source string into a Block AST.
///
/// Returns `ERR_PARSE` for syntax errors, `ERR_COMPILE` for constraint violations
/// (disallowed identifiers, `tool` misuse, variadics, etc.).
pub fn parse(source: &str) -> Result<Block, ParseError> {
    let tokens = lexer::Lexer::new(source).tokenize()?;
    let mut parser = Parser::new(tokens);
    let block = parser.parse_block()?;
    parser.expect_eof()?;
    Ok(block)
}

// ---------------------------------------------------------------------------
// Disallowed identifiers
// ---------------------------------------------------------------------------

const DISALLOWED_IDENTS: &[&str] = &[
    "debug",
    "io",
    "os",
    "package",
    "require",
    "load",
    "dofile",
    "loadfile",
    "loadstring",
    "collectgarbage",
    "setmetatable",
    "getmetatable",
    "rawget",
    "rawset",
    "setfenv",
    "getfenv",
    "coroutine",
];

fn is_disallowed(name: &str) -> bool {
    DISALLOWED_IDENTS.contains(&name)
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser {
    tokens: Vec<SpannedToken>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<SpannedToken>) -> Self {
        Parser { tokens, pos: 0 }
    }

    // --- Token access ---

    fn peek(&self) -> &SpannedToken {
        &self.tokens[self.pos]
    }

    fn peek2(&self) -> Option<&SpannedToken> {
        self.tokens.get(self.pos + 1)
    }

    fn advance(&mut self) -> &SpannedToken {
        let tok = &self.tokens[self.pos];
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    fn check(&self, t: &Token) -> bool {
        &self.peek().token == t
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek().token, Token::Eof)
    }

    fn current_span(&self) -> Span {
        self.peek().span
    }

    /// Consume a specific token or return an error.
    fn expect(&mut self, expected: &Token, label: &'static str) -> Result<Span, ParseError> {
        if &self.peek().token == expected {
            Ok(self.advance().span)
        } else {
            Err(ParseError::UnexpectedToken {
                span: self.current_span(),
                expected: label,
                got: token_description(&self.peek().token),
            })
        }
    }

    fn expect_ident(&mut self) -> Result<(String, Span), ParseError> {
        match self.peek().token.clone() {
            Token::Ident(name) => {
                let span = self.advance().span;
                Ok((name, span))
            }
            _ => Err(ParseError::UnexpectedToken {
                span: self.current_span(),
                expected: "identifier",
                got: token_description(&self.peek().token),
            }),
        }
    }

    fn expect_eof(&self) -> Result<(), ParseError> {
        if self.at_eof() {
            Ok(())
        } else {
            Err(ParseError::UnexpectedToken {
                span: self.current_span(),
                expected: "end of file",
                got: token_description(&self.peek().token),
            })
        }
    }

    // --- Block terminator check ---

    fn at_block_end(&self) -> bool {
        matches!(
            self.peek().token,
            Token::KwEnd | Token::KwElse | Token::KwElseif | Token::KwReturn | Token::Eof
        )
    }

    // -----------------------------------------------------------------------
    // Grammar: block
    // -----------------------------------------------------------------------

    fn parse_block(&mut self) -> Result<Block, ParseError> {
        let span = self.current_span();
        let mut stmts = Vec::new();
        let mut ret = None;

        loop {
            // Skip optional semicolons
            while self.check(&Token::Semicolon) {
                self.advance();
            }

            if self.check(&Token::KwReturn) {
                ret = Some(self.parse_return()?);
                // Optional semicolon after return
                if self.check(&Token::Semicolon) {
                    self.advance();
                }
                break;
            }

            if self.at_block_end() {
                break;
            }

            let stmt = self.parse_stat()?;
            stmts.push(stmt);
        }

        Ok(Block { stmts, ret, span })
    }

    fn parse_return(&mut self) -> Result<ReturnStmt, ParseError> {
        let span = self.current_span();
        self.advance(); // consume `return`

        let value = if self.at_block_end() || self.check(&Token::Semicolon) {
            None
        } else {
            Some(self.parse_expr()?)
        };

        Ok(ReturnStmt { value, span })
    }

    // -----------------------------------------------------------------------
    // Grammar: statements
    // -----------------------------------------------------------------------

    fn parse_stat(&mut self) -> Result<Stmt, ParseError> {
        match self.peek().token.clone() {
            Token::KwLocal => self.parse_local(),
            Token::KwIf => self.parse_if(),
            Token::KwWhile => self.parse_while(),
            Token::KwFor => self.parse_for(),
            Token::KwFunction => self.parse_function_decl(),
            Token::KwDo => self.parse_do(),
            Token::KwBreak => {
                let span = self.advance().span;
                Ok(Stmt::Break(span))
            }
            _ => self.parse_expr_or_assign(),
        }
    }

    fn parse_local(&mut self) -> Result<Stmt, ParseError> {
        let span = self.advance().span; // consume `local`

        if self.check(&Token::KwFunction) {
            self.advance(); // consume `function`
            let (name, name_span) = self.expect_ident()?;
            let func = self.parse_func_body()?;
            return Ok(Stmt::LocalFunctionDecl(LocalFunctionDecl {
                name,
                name_span,
                func,
                span,
            }));
        }

        // local name [, name]* [= expr [, expr]*]
        let mut names = Vec::new();
        let (first_name, first_span) = self.expect_ident()?;
        names.push((first_name, first_span));
        while self.check(&Token::Comma) {
            self.advance();
            let (n, s) = self.expect_ident()?;
            names.push((n, s));
        }

        let mut values = Vec::new();
        if self.check(&Token::Assign) {
            self.advance();
            values.push(self.parse_expr()?);
            while self.check(&Token::Comma) {
                self.advance();
                values.push(self.parse_expr()?);
            }
        }

        Ok(Stmt::LocalDecl(LocalDecl {
            names,
            values,
            span,
        }))
    }

    fn parse_if(&mut self) -> Result<Stmt, ParseError> {
        let span = self.advance().span; // consume `if`
        let condition = self.parse_expr()?;
        self.expect(&Token::KwThen, "`then`")?;
        let then_block = self.parse_block()?;

        let mut elseif_clauses = Vec::new();
        let mut else_block = None;

        loop {
            if self.check(&Token::KwElseif) {
                let clause_span = self.advance().span;
                let cond = self.parse_expr()?;
                self.expect(&Token::KwThen, "`then`")?;
                let block = self.parse_block()?;
                elseif_clauses.push(ElseifClause {
                    condition: cond,
                    block,
                    span: clause_span,
                });
            } else if self.check(&Token::KwElse) {
                self.advance();
                else_block = Some(self.parse_block()?);
                break;
            } else {
                break;
            }
        }

        self.expect(&Token::KwEnd, "`end`")?;
        Ok(Stmt::If(IfStmt {
            condition,
            then_block,
            elseif_clauses,
            else_block,
            span,
        }))
    }

    fn parse_while(&mut self) -> Result<Stmt, ParseError> {
        let span = self.advance().span; // consume `while`
        let condition = self.parse_expr()?;
        self.expect(&Token::KwDo, "`do`")?;
        let block = self.parse_block()?;
        self.expect(&Token::KwEnd, "`end`")?;
        Ok(Stmt::While(WhileStmt {
            condition,
            block,
            span,
        }))
    }

    fn parse_for(&mut self) -> Result<Stmt, ParseError> {
        let span = self.advance().span; // consume `for`

        let (first_var, first_var_span) = self.expect_ident()?;

        if self.check(&Token::Assign) {
            // Numeric for: `for var = start, limit [, step] do`
            self.advance();
            let start = self.parse_expr()?;
            self.expect(&Token::Comma, "`,`")?;
            let limit = self.parse_expr()?;
            let step = if self.check(&Token::Comma) {
                self.advance();
                Some(self.parse_expr()?)
            } else {
                None
            };
            self.expect(&Token::KwDo, "`do`")?;
            let block = self.parse_block()?;
            self.expect(&Token::KwEnd, "`end`")?;
            return Ok(Stmt::NumericFor(NumericFor {
                var: first_var,
                var_span: first_var_span,
                start,
                limit,
                step,
                block,
                span,
            }));
        }

        // Generic for: `for var [, var]* in iter do`
        let mut vars = vec![(first_var, first_var_span)];
        while self.check(&Token::Comma) {
            self.advance();
            let (v, vs) = self.expect_ident()?;
            vars.push((v, vs));
        }
        self.expect(&Token::KwIn, "`in`")?;
        let mut iterators = vec![self.parse_expr()?];
        while self.check(&Token::Comma) {
            self.advance();
            iterators.push(self.parse_expr()?);
        }
        self.expect(&Token::KwDo, "`do`")?;
        let block = self.parse_block()?;
        self.expect(&Token::KwEnd, "`end`")?;
        Ok(Stmt::GenericFor(GenericFor {
            vars,
            iterators,
            block,
            span,
        }))
    }

    fn parse_function_decl(&mut self) -> Result<Stmt, ParseError> {
        let span = self.advance().span; // consume `function`

        // Name: a[.b[.c]][:method]
        let (first, first_span) = self.expect_ident()?;
        let mut parts = vec![(first, first_span)];
        let mut method = None;

        loop {
            if self.check(&Token::Dot) {
                self.advance();
                let (part, ps) = self.expect_ident()?;
                parts.push((part, ps));
            } else if self.check(&Token::Colon) {
                self.advance();
                let (m, ms) = self.expect_ident()?;
                method = Some((m, ms));
                break;
            } else {
                break;
            }
        }

        let func = self.parse_func_body()?;
        Ok(Stmt::FunctionDecl(FunctionDecl {
            name: FuncName { parts, method },
            func,
            span,
        }))
    }

    fn parse_do(&mut self) -> Result<Stmt, ParseError> {
        let span = self.advance().span; // consume `do`
        let block = self.parse_block()?;
        self.expect(&Token::KwEnd, "`end`")?;
        Ok(Stmt::Do(DoBlock { block, span }))
    }

    /// Parse either an assignment or an expression statement (function call).
    fn parse_expr_or_assign(&mut self) -> Result<Stmt, ParseError> {
        let expr = self.parse_suffixed_expr()?;

        if self.check(&Token::Assign) {
            let span = self.advance().span; // consume `=`
            let value = self.parse_expr()?;
            let target = expr_to_assign_target(expr, span)?;
            return Ok(Stmt::Assign(Assign {
                target,
                value,
                span,
            }));
        }

        // Must be a call expression to be valid as a statement
        let span = expr.span();
        match expr {
            Expr::Call(_) | Expr::MethodCall(_) => Ok(Stmt::ExprStmt(ExprStmt { expr, span })),
            _ => Err(ParseError::UnexpectedToken {
                span,
                expected: "function call or assignment",
                got: "expression".into(),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Grammar: function body
    // -----------------------------------------------------------------------

    fn parse_func_body(&mut self) -> Result<FuncBody, ParseError> {
        let span = self.current_span();
        self.expect(&Token::LParen, "`(`")?;

        let mut params = Vec::new();
        if !self.check(&Token::RParen) {
            loop {
                if self.check(&Token::DotDotDot) {
                    let s = self.advance().span;
                    return Err(ParseError::VariadicNotAllowed { span: s });
                }
                let (name, ns) = self.expect_ident()?;
                params.push((name, ns));
                if !self.check(&Token::Comma) {
                    break;
                }
                self.advance();
                // Allow trailing comma before `)` — not standard but harmless
            }
        }

        self.expect(&Token::RParen, "`)`")?;
        let block = self.parse_block()?;
        self.expect(&Token::KwEnd, "`end`")?;
        Ok(FuncBody {
            params,
            block,
            span,
        })
    }

    // -----------------------------------------------------------------------
    // Grammar: expressions
    // -----------------------------------------------------------------------

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_binop(0)
    }

    fn parse_binop(&mut self, min_prec: u8) -> Result<Expr, ParseError> {
        let mut left = self.parse_unop()?;

        loop {
            let Some((op, prec, right_assoc)) = self.peek_binop() else {
                break;
            };
            if prec < min_prec {
                break;
            }
            let span = self.advance().span;
            let next_min = if right_assoc { prec } else { prec + 1 };
            let right = self.parse_binop(next_min)?;
            left = Expr::BinOp(BinOp {
                op,
                left: Box::new(left),
                right: Box::new(right),
                span,
            });
        }

        Ok(left)
    }

    /// Returns `(op_kind, precedence, right_associative)` for the current token if it's a binary op.
    fn peek_binop(&self) -> Option<(BinOpKind, u8, bool)> {
        match &self.peek().token {
            Token::KwOr => Some((BinOpKind::Or, 1, false)),
            Token::KwAnd => Some((BinOpKind::And, 2, false)),
            Token::Lt => Some((BinOpKind::Lt, 3, false)),
            Token::LtEq => Some((BinOpKind::Le, 3, false)),
            Token::Gt => Some((BinOpKind::Gt, 3, false)),
            Token::GtEq => Some((BinOpKind::Ge, 3, false)),
            Token::Eq => Some((BinOpKind::Eq, 3, false)),
            Token::TildeEq => Some((BinOpKind::Ne, 3, false)),
            Token::DotDot => Some((BinOpKind::Concat, 4, true)),
            Token::Plus => Some((BinOpKind::Add, 5, false)),
            Token::Minus => Some((BinOpKind::Sub, 5, false)),
            Token::Star => Some((BinOpKind::Mul, 6, false)),
            Token::SlashSlash => Some((BinOpKind::IDiv, 6, false)),
            Token::Percent => Some((BinOpKind::Mod, 6, false)),
            _ => None,
        }
    }

    fn parse_unop(&mut self) -> Result<Expr, ParseError> {
        let span = self.current_span();
        match self.peek().token.clone() {
            Token::KwNot => {
                self.advance();
                let operand = self.parse_unop()?;
                Ok(Expr::UnOp(UnOp {
                    op: UnOpKind::Not,
                    operand: Box::new(operand),
                    span,
                }))
            }
            Token::Minus => {
                self.advance();
                let operand = self.parse_unop()?;
                Ok(Expr::UnOp(UnOp {
                    op: UnOpKind::Neg,
                    operand: Box::new(operand),
                    span,
                }))
            }
            Token::Hash => {
                self.advance();
                let operand = self.parse_unop()?;
                Ok(Expr::UnOp(UnOp {
                    op: UnOpKind::Len,
                    operand: Box::new(operand),
                    span,
                }))
            }
            _ => self.parse_suffixed_expr(),
        }
    }

    /// Parse a primary atom with optional suffix chain (field, index, call, method).
    fn parse_suffixed_expr(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_primary_atom()?;

        loop {
            match self.peek().token.clone() {
                Token::Dot => {
                    let dot_span = self.advance().span; // consume `.`
                    let (field, _) = self.expect_ident()?;
                    expr = Expr::Field(Box::new(expr), field, dot_span);
                }
                Token::LBracket => {
                    let span = self.advance().span; // consume `[`
                    let key = self.parse_expr()?;
                    self.expect(&Token::RBracket, "`]`")?;
                    expr = Expr::Index(Box::new(expr), Box::new(key), span);
                }
                Token::Colon => {
                    let span = self.advance().span; // consume `:`
                    let (method, method_span) = self.expect_ident()?;
                    let args = self.parse_call_args()?;
                    expr = Expr::MethodCall(MethodCall {
                        object: Box::new(expr),
                        method,
                        method_span,
                        args,
                        span,
                    });
                }
                Token::LParen | Token::StringLit(_) | Token::LBrace => {
                    let span = expr.span();
                    let args = self.parse_call_args()?;
                    expr = Expr::Call(Call {
                        func: Box::new(expr),
                        args,
                        span,
                    });
                }
                _ => break,
            }
        }

        Ok(expr)
    }

    fn parse_primary_atom(&mut self) -> Result<Expr, ParseError> {
        let span = self.current_span();
        match self.peek().token.clone() {
            Token::KwNil => {
                self.advance();
                Ok(Expr::Nil(span))
            }
            Token::KwTrue => {
                self.advance();
                Ok(Expr::True(span))
            }
            Token::KwFalse => {
                self.advance();
                Ok(Expr::False(span))
            }
            Token::Integer(n) => {
                self.advance();
                Ok(Expr::Integer(n, span))
            }
            Token::StringLit(b) => {
                self.advance();
                Ok(Expr::StringLit(b, span))
            }

            Token::DotDotDot => {
                self.advance();
                // Accepted syntactically, rejected at compile time
                Err(ParseError::VariadicNotAllowed { span })
            }

            Token::Ident(name) => {
                self.advance();

                // Check for `tool` special handling
                if name == "tool" {
                    return self.parse_tool_or_error(span);
                }

                // Check for disallowed identifiers
                if is_disallowed(&name) {
                    return Err(ParseError::DisallowedIdent { span, name });
                }

                Ok(Expr::Name(name, span))
            }

            Token::LParen => {
                self.advance(); // consume `(`
                let expr = self.parse_expr()?;
                self.expect(&Token::RParen, "`)`")?;
                Ok(expr)
            }

            Token::KwFunction => {
                self.advance(); // consume `function`
                let body = self.parse_func_body()?;
                Ok(Expr::FuncDef(Box::new(body), span))
            }

            Token::LBrace => self.parse_table_constructor(),

            _ => Err(ParseError::ExpectedExpr { span }),
        }
    }

    /// Called after seeing `tool` as an identifier.
    ///
    /// The spec says `tool` is a compile-time namespace. The parser enforces:
    /// - bare `tool` (not followed by `.`) is a compile error.
    /// - `tool.<anything-other-than-call>` is a compile error.
    /// - `tool.call` followed by `(` is emitted as a regular Call AST node.
    /// - `tool.call` NOT followed by `(` is allowed as a parsed expression so
    ///   the compiler can handle the `pcall(tool.call, ...)` special form (§3.4).
    ///   The compiler (Phase 4) will reject any other use of `tool.call` as a value.
    fn parse_tool_or_error(&mut self, tool_span: Span) -> Result<Expr, ParseError> {
        // Must be followed by `.`
        if !self.check(&Token::Dot) {
            return Err(ParseError::ToolAsValue { span: tool_span });
        }
        self.advance(); // consume `.`

        // Must be followed by `call`
        match self.peek().token.clone() {
            Token::Ident(ref name) if name == "call" => {
                let call_span = self.advance().span; // consume `call`
                // If followed by `(`, emit as a Call node
                if self.check(&Token::LParen) {
                    let func = Expr::Field(
                        Box::new(Expr::Name("tool".into(), tool_span)),
                        "call".into(),
                        call_span,
                    );
                    let args = self.parse_call_args()?;
                    Ok(Expr::Call(Call {
                        func: Box::new(func),
                        args,
                        span: tool_span,
                    }))
                } else {
                    // `tool.call` as a reference (e.g. argument to pcall).
                    // Accepted syntactically; the compiler validates context.
                    Ok(Expr::Field(
                        Box::new(Expr::Name("tool".into(), tool_span)),
                        "call".into(),
                        call_span,
                    ))
                }
            }
            _ => Err(ParseError::ToolAsValue { span: tool_span }),
        }
    }

    fn parse_call_args(&mut self) -> Result<Vec<Expr>, ParseError> {
        match self.peek().token.clone() {
            Token::LParen => {
                self.advance(); // consume `(`
                let mut args = Vec::new();
                if !self.check(&Token::RParen) {
                    args.push(self.parse_expr()?);
                    while self.check(&Token::Comma) {
                        self.advance();
                        args.push(self.parse_expr()?);
                    }
                }
                self.expect(&Token::RParen, "`)`")?;
                Ok(args)
            }
            Token::StringLit(b) => {
                let span = self.advance().span;
                Ok(vec![Expr::StringLit(b, span)])
            }
            Token::LBrace => {
                let tbl = self.parse_table_constructor()?;
                Ok(vec![tbl])
            }
            _ => Err(ParseError::UnexpectedToken {
                span: self.current_span(),
                expected: "function arguments",
                got: token_description(&self.peek().token),
            }),
        }
    }

    fn parse_table_constructor(&mut self) -> Result<Expr, ParseError> {
        let span = self.current_span();
        self.expect(&Token::LBrace, "`{`")?;
        let mut fields = Vec::new();

        while !self.check(&Token::RBrace) {
            let field = self.parse_table_field()?;
            fields.push(field);
            // Fields separated by `,` or `;`; trailing separator allowed
            if self.check(&Token::Comma) || self.check(&Token::Semicolon) {
                self.advance();
            } else {
                break;
            }
        }

        self.expect(&Token::RBrace, "`}`")?;
        Ok(Expr::TableConstructor(TableConstructor { fields, span }))
    }

    fn parse_table_field(&mut self) -> Result<TableField, ParseError> {
        let span = self.current_span();

        // `[expr] = expr`
        if self.check(&Token::LBracket) {
            self.advance();
            let key = self.parse_expr()?;
            self.expect(&Token::RBracket, "`]`")?;
            self.expect(&Token::Assign, "`=`")?;
            let value = self.parse_expr()?;
            return Ok(TableField::ExplicitKey { key, value, span });
        }

        // `name = expr` — only if next-next is `=`
        if let Token::Ident(name) = self.peek().token.clone() {
            if let Some(next) = self.peek2() {
                if next.token == Token::Assign {
                    let name_span = self.advance().span; // consume name
                    self.advance(); // consume `=`
                    let value = self.parse_expr()?;
                    return Ok(TableField::NamedKey {
                        name,
                        name_span,
                        value,
                        span,
                    });
                }
            }
        }

        // Positional
        let value = self.parse_expr()?;
        Ok(TableField::Positional { value, span })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn expr_to_assign_target(expr: Expr, span: Span) -> Result<AssignTarget, ParseError> {
    match expr {
        Expr::Name(name, s) => Ok(AssignTarget::Name(name, s)),
        Expr::Field(obj, field, s) => {
            // `t.k = v` → Index with string key
            let key = Expr::StringLit(field.into_bytes(), s);
            Ok(AssignTarget::Index(obj, Box::new(key), s))
        }
        Expr::Index(obj, key, s) => Ok(AssignTarget::Index(obj, key, s)),
        _ => Err(ParseError::UnexpectedToken {
            span,
            expected: "assignable target (variable or table field)",
            got: "expression".into(),
        }),
    }
}

fn token_description(tok: &Token) -> String {
    match tok {
        Token::Eof => "end of file".into(),
        Token::Ident(n) => format!("`{}`", n),
        Token::Integer(n) => format!("{}", n),
        Token::StringLit(_) => "string literal".into(),
        Token::KwAnd => "`and`".into(),
        Token::KwBreak => "`break`".into(),
        Token::KwDo => "`do`".into(),
        Token::KwElse => "`else`".into(),
        Token::KwElseif => "`elseif`".into(),
        Token::KwEnd => "`end`".into(),
        Token::KwFalse => "`false`".into(),
        Token::KwFor => "`for`".into(),
        Token::KwFunction => "`function`".into(),
        Token::KwIf => "`if`".into(),
        Token::KwIn => "`in`".into(),
        Token::KwLocal => "`local`".into(),
        Token::KwNil => "`nil`".into(),
        Token::KwNot => "`not`".into(),
        Token::KwOr => "`or`".into(),
        Token::KwReturn => "`return`".into(),
        Token::KwThen => "`then`".into(),
        Token::KwTrue => "`true`".into(),
        Token::KwWhile => "`while`".into(),
        Token::Plus => "`+`".into(),
        Token::Minus => "`-`".into(),
        Token::Star => "`*`".into(),
        Token::SlashSlash => "`//`".into(),
        Token::Percent => "`%`".into(),
        Token::DotDot => "`..`".into(),
        Token::DotDotDot => "`...`".into(),
        Token::Hash => "`#`".into(),
        Token::Eq => "`==`".into(),
        Token::TildeEq => "`~=`".into(),
        Token::Lt => "`<`".into(),
        Token::LtEq => "`<=`".into(),
        Token::Gt => "`>`".into(),
        Token::GtEq => "`>=`".into(),
        Token::Assign => "`=`".into(),
        Token::LParen => "`(`".into(),
        Token::RParen => "`)`".into(),
        Token::LBrace => "`{`".into(),
        Token::RBrace => "`}`".into(),
        Token::LBracket => "`[`".into(),
        Token::RBracket => "`]`".into(),
        Token::Semicolon => "`;`".into(),
        Token::Colon => "`:`".into(),
        Token::Comma => "`,`".into(),
        Token::Dot => "`.`".into(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(src: &str) -> Block {
        parse(src).unwrap_or_else(|e| panic!("parse failed: {:?}", e))
    }

    fn parse_err(src: &str) -> ParseError {
        parse(src).expect_err("expected parse error")
    }

    // --- Local declarations ---

    #[test]
    fn local_simple() {
        let block = parse_ok("local x = 42");
        assert_eq!(block.stmts.len(), 1);
        let Stmt::LocalDecl(ld) = &block.stmts[0] else {
            panic!()
        };
        assert_eq!(ld.names[0].0, "x");
        assert!(matches!(ld.values[0], Expr::Integer(42, _)));
    }

    #[test]
    fn local_multi_assign() {
        let block = parse_ok("local a, b = 1, 2");
        let Stmt::LocalDecl(ld) = &block.stmts[0] else {
            panic!()
        };
        assert_eq!(ld.names.len(), 2);
        assert_eq!(ld.values.len(), 2);
    }

    // --- Assignments ---

    #[test]
    fn simple_assign() {
        let block = parse_ok("x = 1");
        let Stmt::Assign(a) = &block.stmts[0] else {
            panic!()
        };
        assert!(matches!(a.target, AssignTarget::Name(ref n, _) if n == "x"));
    }

    #[test]
    fn table_index_assign() {
        let block = parse_ok("t[k] = v");
        let Stmt::Assign(a) = &block.stmts[0] else {
            panic!()
        };
        assert!(matches!(a.target, AssignTarget::Index(_, _, _)));
    }

    #[test]
    fn table_field_assign() {
        let block = parse_ok("t.k = v");
        let Stmt::Assign(a) = &block.stmts[0] else {
            panic!()
        };
        // `.k` is desugared to Index with string key
        assert!(matches!(a.target, AssignTarget::Index(_, _, _)));
    }

    // --- If statement ---

    #[test]
    fn if_basic() {
        let block = parse_ok("if true then end");
        assert!(matches!(block.stmts[0], Stmt::If(_)));
    }

    #[test]
    fn if_else() {
        let block = parse_ok("if x then local a = 1 else local b = 2 end");
        let Stmt::If(stmt) = &block.stmts[0] else {
            panic!()
        };
        assert!(stmt.else_block.is_some());
    }

    #[test]
    fn if_elseif() {
        let block = parse_ok("if a then elseif b then end");
        let Stmt::If(stmt) = &block.stmts[0] else {
            panic!()
        };
        assert_eq!(stmt.elseif_clauses.len(), 1);
    }

    // --- While ---

    #[test]
    fn while_basic() {
        let block = parse_ok("while x do end");
        assert!(matches!(block.stmts[0], Stmt::While(_)));
    }

    // --- Numeric for ---

    #[test]
    fn numeric_for_basic() {
        let block = parse_ok("for i = 1, 10 do end");
        let Stmt::NumericFor(f) = &block.stmts[0] else {
            panic!()
        };
        assert_eq!(f.var, "i");
        assert!(f.step.is_none());
    }

    #[test]
    fn numeric_for_with_step() {
        let block = parse_ok("for i = 1, 10, 2 do end");
        let Stmt::NumericFor(f) = &block.stmts[0] else {
            panic!()
        };
        assert!(f.step.is_some());
    }

    // --- Generic for ---

    #[test]
    fn generic_for() {
        let block = parse_ok("for k, v in pairs_sorted(t) do end");
        let Stmt::GenericFor(f) = &block.stmts[0] else {
            panic!()
        };
        assert_eq!(f.vars.len(), 2);
    }

    // --- Function declarations ---

    #[test]
    fn function_decl_simple() {
        let block = parse_ok("function f(a, b) return a end");
        assert!(matches!(block.stmts[0], Stmt::FunctionDecl(_)));
    }

    #[test]
    fn local_function_decl() {
        let block = parse_ok("local function g() end");
        assert!(matches!(block.stmts[0], Stmt::LocalFunctionDecl(_)));
    }

    #[test]
    fn method_function_decl() {
        let block = parse_ok("function t:method(x) end");
        let Stmt::FunctionDecl(f) = &block.stmts[0] else {
            panic!()
        };
        assert!(f.name.method.is_some());
    }

    // --- Break ---

    #[test]
    fn break_stmt() {
        let block = parse_ok("while true do break end");
        let Stmt::While(w) = &block.stmts[0] else {
            panic!()
        };
        assert!(matches!(w.block.stmts[0], Stmt::Break(_)));
    }

    // --- Precedence ---

    #[test]
    fn precedence_mul_before_add() {
        // 1 + 2 * 3 → BinOp(Add, 1, BinOp(Mul, 2, 3))
        let block = parse_ok("local x = 1 + 2 * 3");
        let Stmt::LocalDecl(ld) = &block.stmts[0] else {
            panic!()
        };
        let Expr::BinOp(outer) = &ld.values[0] else {
            panic!()
        };
        assert_eq!(outer.op, BinOpKind::Add);
        assert!(matches!(*outer.right, Expr::BinOp(ref b) if b.op == BinOpKind::Mul));
    }

    #[test]
    fn precedence_and_before_or() {
        // a or b and c → or(a, and(b, c))
        let block = parse_ok("local x = a or b and c");
        let Stmt::LocalDecl(ld) = &block.stmts[0] else {
            panic!()
        };
        let Expr::BinOp(outer) = &ld.values[0] else {
            panic!()
        };
        assert_eq!(outer.op, BinOpKind::Or);
        assert!(matches!(*outer.right, Expr::BinOp(ref b) if b.op == BinOpKind::And));
    }

    #[test]
    fn concat_right_assoc() {
        // a .. b .. c → a .. (b .. c)
        let block = parse_ok("local x = a .. b .. c");
        let Stmt::LocalDecl(ld) = &block.stmts[0] else {
            panic!()
        };
        let Expr::BinOp(outer) = &ld.values[0] else {
            panic!()
        };
        assert_eq!(outer.op, BinOpKind::Concat);
        assert!(matches!(*outer.right, Expr::BinOp(ref b) if b.op == BinOpKind::Concat));
    }

    // --- Function calls ---

    #[test]
    fn function_call_expr_stmt() {
        let block = parse_ok("f(1, 2, 3)");
        assert!(matches!(block.stmts[0], Stmt::ExprStmt(_)));
    }

    #[test]
    fn method_call() {
        let block = parse_ok("t:method(x)");
        let Stmt::ExprStmt(es) = &block.stmts[0] else {
            panic!()
        };
        assert!(matches!(es.expr, Expr::MethodCall(_)));
    }

    // --- Table constructor ---

    #[test]
    fn table_constructor() {
        let block = parse_ok("local t = { 1, 2, k = 3 }");
        let Stmt::LocalDecl(ld) = &block.stmts[0] else {
            panic!()
        };
        let Expr::TableConstructor(tc) = &ld.values[0] else {
            panic!()
        };
        assert_eq!(tc.fields.len(), 3);
        assert!(matches!(tc.fields[0], TableField::Positional { .. }));
        assert!(matches!(tc.fields[2], TableField::NamedKey { .. }));
    }

    #[test]
    fn table_explicit_key() {
        let block = parse_ok("local t = { [1+1] = 42 }");
        let Stmt::LocalDecl(ld) = &block.stmts[0] else {
            panic!()
        };
        let Expr::TableConstructor(tc) = &ld.values[0] else {
            panic!()
        };
        assert!(matches!(tc.fields[0], TableField::ExplicitKey { .. }));
    }

    // --- tool.call ---

    #[test]
    fn tool_call_ok() {
        let block = parse_ok(r#"local r = tool.call("x", {})"#);
        let Stmt::LocalDecl(ld) = &block.stmts[0] else {
            panic!()
        };
        let Expr::Call(c) = &ld.values[0] else {
            panic!()
        };
        // func should be Field(Name("tool"), "call")
        assert!(matches!(*c.func, Expr::Field(_, ref field, _) if field == "call"));
    }

    #[test]
    fn tool_as_value_rejected() {
        let err = parse_err("local t = tool");
        assert!(matches!(err, ParseError::ToolAsValue { .. }));
        assert_eq!(err.code(), "ERR_COMPILE");
    }

    #[test]
    fn tool_dot_bad_field_rejected() {
        let err = parse_err("tool.bad(1, 2)");
        assert!(matches!(err, ParseError::ToolAsValue { .. }));
    }

    // --- Disallowed identifiers ---

    #[test]
    fn require_disallowed() {
        let err = parse_err("require('foo')");
        assert!(matches!(err, ParseError::DisallowedIdent { ref name, .. } if name == "require"));
        assert_eq!(err.code(), "ERR_COMPILE");
    }

    #[test]
    fn coroutine_disallowed() {
        let err = parse_err("coroutine.create(f)");
        assert!(matches!(err, ParseError::DisallowedIdent { .. }));
    }

    // --- Variadic ---

    #[test]
    fn variadic_in_params_rejected() {
        let err = parse_err("function f(...) end");
        assert!(matches!(err, ParseError::VariadicNotAllowed { .. }));
        assert_eq!(err.code(), "ERR_COMPILE");
    }

    // --- Single slash ---

    #[test]
    fn single_slash_rejected() {
        let err = parse_err("local x = 1 / 2");
        assert!(matches!(err, ParseError::SingleSlash { .. }));
        assert_eq!(err.code(), "ERR_PARSE");
    }

    // --- Return ---

    #[test]
    fn return_no_value() {
        let block = parse_ok("return");
        assert!(block.ret.is_some());
        assert!(block.ret.unwrap().value.is_none());
    }

    #[test]
    fn return_with_value() {
        let block = parse_ok("return 42");
        let ret = block.ret.unwrap();
        assert!(matches!(ret.value, Some(Expr::Integer(42, _))));
    }

    // --- Missing `end` ---

    #[test]
    fn missing_end_error() {
        let err = parse_err("if true then");
        assert!(matches!(err, ParseError::UnexpectedToken { .. }));
    }

    // --- Anonymous function ---

    #[test]
    fn anon_function_expr() {
        let block = parse_ok("local f = function(x) return x end");
        let Stmt::LocalDecl(ld) = &block.stmts[0] else {
            panic!()
        };
        assert!(matches!(ld.values[0], Expr::FuncDef(_, _)));
    }

    // --- Do block ---

    #[test]
    fn do_block() {
        let block = parse_ok("do local x = 1 end");
        assert!(matches!(block.stmts[0], Stmt::Do(_)));
    }

    // --- Nested structures ---

    #[test]
    fn nested_if_for() {
        parse_ok("if x then for i = 1, 10 do if y then end end end");
    }

    // --- Multi-return syntax (pcall) ---

    #[test]
    fn multi_assign_local() {
        let block = parse_ok("local a, b = pcall(f)");
        let Stmt::LocalDecl(ld) = &block.stmts[0] else {
            panic!()
        };
        assert_eq!(ld.names.len(), 2);
    }

    // --- Unary chaining ---

    #[test]
    fn unary_chain() {
        let block = parse_ok("local x = not not true");
        let Stmt::LocalDecl(ld) = &block.stmts[0] else {
            panic!()
        };
        assert!(matches!(ld.values[0], Expr::UnOp(ref u) if u.op == UnOpKind::Not));
    }

    // --- Full example scripts ---

    #[test]
    fn full_agent_script() {
        let src = r#"
local ok, result = pcall(tool.call, "web_search", {
  query = "test"
})
if not ok then
  local out = {}
  for i, item in ipairs(result.items) do
    out[i] = { title = item.title }
  end
  return { status = "ok", results = out }
end
return { status = "error" }
"#;
        parse_ok(src);
    }
}
