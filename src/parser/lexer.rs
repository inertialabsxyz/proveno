#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

/// Byte offset span + line number for a token or AST node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub line: u32,
}

impl Span {
    pub fn new(start: usize, end: usize, line: u32) -> Self {
        Span { start, end, line }
    }

    /// Dummy span used when a real position is unavailable.
    pub fn dummy() -> Self {
        Span {
            start: 0,
            end: 0,
            line: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    // Literals
    Integer(i64),
    StringLit(Vec<u8>),

    // Identifier (non-keyword)
    Ident(String),

    // Keywords
    KwAnd,
    KwBreak,
    KwDo,
    KwElse,
    KwElseif,
    KwEnd,
    KwFalse,
    KwFor,
    KwFunction,
    KwIf,
    KwIn,
    KwLocal,
    KwNil,
    KwNot,
    KwOr,
    KwReturn,
    KwThen,
    KwTrue,
    KwWhile,

    // Punctuation / operators
    Plus,       // +
    Minus,      // -
    Star,       // *
    SlashSlash, // //
    Percent,    // %
    DotDot,     // ..
    DotDotDot,  // ...
    Hash,       // #
    Eq,         // ==
    TildeEq,    // ~=
    Lt,         // <
    LtEq,       // <=
    Gt,         // >
    GtEq,       // >=
    Assign,     // =
    LParen,     // (
    RParen,     // )
    LBrace,     // {
    RBrace,     // }
    LBracket,   // [
    RBracket,   // ]
    Semicolon,  // ;
    Colon,      // :
    Comma,      // ,
    Dot,        // .

    Eof,
}

#[derive(Clone, Debug)]
pub struct SpannedToken {
    pub token: Token,
    pub span: Span,
}

// ---------------------------------------------------------------------------
// Parse errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    // ---- Lex-time errors ----
    /// `/` used instead of `//`
    SingleSlash { span: Span },
    /// Floating-point literal in source
    FloatLiteral { span: Span },
    /// Integer literal out of i64 range
    IntegerOverflow { span: Span },
    /// Unrecognized escape sequence
    BadEscape { span: Span },
    /// String literal exceeds max_string_len (64 KB)
    StringTooLong { span: Span },
    /// Unexpected character
    UnexpectedChar { span: Span, ch: char },
    /// Unterminated string literal
    UnterminatedString { span: Span },
    /// Unterminated block comment or long string
    UnterminatedComment { span: Span },

    // ---- Parse-time errors ----
    /// Unexpected token
    UnexpectedToken {
        span: Span,
        expected: &'static str,
        got: String,
    },
    /// Expected an expression
    ExpectedExpr { span: Span },

    // ---- Compile-time constraint violations ----
    /// `tool` used as a value (not in `tool.call(...)` form)
    ToolAsValue { span: Span },
    /// Identifier is explicitly disallowed (debug, io, os, require, etc.)
    DisallowedIdent { span: Span, name: String },
    /// `...` syntax in function definition or expression
    VariadicNotAllowed { span: Span },
}

impl ParseError {
    pub fn code(&self) -> &'static str {
        match self {
            ParseError::SingleSlash { .. }
            | ParseError::FloatLiteral { .. }
            | ParseError::IntegerOverflow { .. }
            | ParseError::BadEscape { .. }
            | ParseError::StringTooLong { .. }
            | ParseError::UnexpectedChar { .. }
            | ParseError::UnterminatedString { .. }
            | ParseError::UnterminatedComment { .. }
            | ParseError::UnexpectedToken { .. }
            | ParseError::ExpectedExpr { .. } => "ERR_PARSE",

            ParseError::ToolAsValue { .. }
            | ParseError::DisallowedIdent { .. }
            | ParseError::VariadicNotAllowed { .. } => "ERR_COMPILE",
        }
    }

    pub fn span(&self) -> Span {
        match self {
            ParseError::SingleSlash { span }
            | ParseError::FloatLiteral { span }
            | ParseError::IntegerOverflow { span }
            | ParseError::BadEscape { span }
            | ParseError::StringTooLong { span }
            | ParseError::UnterminatedString { span }
            | ParseError::UnterminatedComment { span }
            | ParseError::UnexpectedToken { span, .. }
            | ParseError::ExpectedExpr { span }
            | ParseError::ToolAsValue { span }
            | ParseError::VariadicNotAllowed { span } => *span,
            ParseError::UnexpectedChar { span, .. } => *span,
            ParseError::DisallowedIdent { span, .. } => *span,
        }
    }

    pub fn message(&self) -> String {
        match self {
            ParseError::SingleSlash { .. } => {
                "use `//` for floor division; the `/` operator is not supported".into()
            }
            ParseError::FloatLiteral { .. } => "floating-point literals are not supported".into(),
            ParseError::IntegerOverflow { .. } => "integer literal out of i64 range".into(),
            ParseError::BadEscape { .. } => "unrecognized escape sequence in string literal".into(),
            ParseError::StringTooLong { .. } => {
                "string literal exceeds maximum length (65536 bytes)".into()
            }
            ParseError::UnexpectedChar { ch, .. } => {
                format!("unexpected character: {:?}", ch)
            }
            ParseError::UnterminatedString { .. } => "unterminated string literal".into(),
            ParseError::UnterminatedComment { .. } => {
                "unterminated block comment or long string".into()
            }
            ParseError::UnexpectedToken { expected, got, .. } => {
                format!("expected {}, got {}", expected, got)
            }
            ParseError::ExpectedExpr { .. } => "expected expression".into(),
            ParseError::ToolAsValue { .. } => {
                "`tool` is a compile-time namespace; only `tool.call(name, args)` is permitted"
                    .into()
            }
            ParseError::DisallowedIdent { name, .. } => {
                format!("`{}` is not available in this VM", name)
            }
            ParseError::VariadicNotAllowed { .. } => {
                "variadic arguments (`...`) are not supported".into()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

const MAX_STRING_LEN: usize = 65536;

pub struct Lexer<'src> {
    src: &'src [u8],
    pos: usize,
    line: u32,
}

impl<'src> Lexer<'src> {
    pub fn new(src: &'src str) -> Self {
        Lexer {
            src: src.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    pub fn tokenize(mut self) -> Result<Vec<SpannedToken>, ParseError> {
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace_and_comments()?;
            if self.pos >= self.src.len() {
                tokens.push(SpannedToken {
                    token: Token::Eof,
                    span: Span::new(self.pos, self.pos, self.line),
                });
                break;
            }
            let tok = self.next_token()?;
            tokens.push(tok);
        }
        Ok(tokens)
    }

    // --- Internal helpers ---

    fn cur(&self) -> u8 {
        if self.pos < self.src.len() {
            self.src[self.pos]
        } else {
            0
        }
    }

    fn peek(&self) -> u8 {
        if self.pos + 1 < self.src.len() {
            self.src[self.pos + 1]
        } else {
            0
        }
    }

    fn advance(&mut self) -> u8 {
        let c = self.cur();
        if c == b'\n' {
            self.line += 1;
        }
        self.pos += 1;
        c
    }

    fn span_from(&self, start: usize, line: u32) -> Span {
        Span::new(start, self.pos, line)
    }

    // --- Whitespace / comments ---

    fn skip_whitespace_and_comments(&mut self) -> Result<(), ParseError> {
        loop {
            // Skip whitespace
            while self.pos < self.src.len() && matches!(self.cur(), b' ' | b'\t' | b'\r' | b'\n') {
                self.advance();
            }

            // Check for comment
            if self.pos + 1 < self.src.len() && self.cur() == b'-' && self.peek() == b'-' {
                self.pos += 2; // consume --

                // Long comment?
                if self.cur() == b'[' {
                    let level = self.count_long_bracket_open();
                    if let Some(lvl) = level {
                        self.skip_long_string(lvl, true)?;
                        continue;
                    }
                }
                // Short comment: skip to end of line
                while self.pos < self.src.len() && self.cur() != b'\n' {
                    self.pos += 1;
                }
                continue;
            }

            break;
        }
        Ok(())
    }

    /// If current position is at `[=*[`, return the level (number of `=`).
    /// Does NOT advance the position.
    fn count_long_bracket_open(&self) -> Option<usize> {
        if self.cur() != b'[' {
            return None;
        }
        let mut i = self.pos + 1;
        let mut level = 0usize;
        while i < self.src.len() && self.src[i] == b'=' {
            level += 1;
            i += 1;
        }
        if i < self.src.len() && self.src[i] == b'[' {
            Some(level)
        } else {
            None
        }
    }

    /// Advance past `[=*[` (the opening bracket at current pos).
    fn consume_long_bracket_open(&mut self, level: usize) {
        self.pos += 1; // [
        self.pos += level; // =...
        self.pos += 1; // [
    }

    /// Skip (or collect) a long string body `]=*]` with the given level.
    /// Returns the raw bytes if collecting, else discards.
    fn skip_long_string(&mut self, level: usize, discard: bool) -> Result<Vec<u8>, ParseError> {
        let start = self.pos - 2; // points back to opening --
        self.consume_long_bracket_open(level);
        // Skip initial newline if present (Lua spec)
        if self.pos < self.src.len() && self.cur() == b'\n' {
            self.advance();
        } else if self.pos + 1 < self.src.len() && self.cur() == b'\r' && self.peek() == b'\n' {
            self.advance();
            self.advance();
        }

        let mut buf = Vec::new();
        loop {
            if self.pos >= self.src.len() {
                return Err(ParseError::UnterminatedComment {
                    span: Span::new(start, self.pos, self.line),
                });
            }
            let c = self.advance();
            if c == b']' {
                // Check for matching close bracket
                let mut eq = 0usize;
                while self.pos < self.src.len() && self.src[self.pos] == b'=' {
                    eq += 1;
                    self.pos += 1;
                }
                if eq == level && self.pos < self.src.len() && self.src[self.pos] == b']' {
                    self.pos += 1; // consume final ]
                    return Ok(buf);
                } else {
                    // Not a close; put back into buf
                    if !discard {
                        buf.push(b']');
                        for _ in 0..eq {
                            buf.push(b'=');
                        }
                    }
                }
            } else {
                if !discard {
                    buf.push(c);
                }
            }
        }
    }

    // --- Main token dispatch ---

    fn next_token(&mut self) -> Result<SpannedToken, ParseError> {
        let start = self.pos;
        let line = self.line;
        let c = self.cur();

        match c {
            b'+' => {
                self.pos += 1;
                Ok(self.tok(Token::Plus, start, line))
            }
            b'-' => {
                self.pos += 1;
                Ok(self.tok(Token::Minus, start, line))
            }
            b'*' => {
                self.pos += 1;
                Ok(self.tok(Token::Star, start, line))
            }
            b'%' => {
                self.pos += 1;
                Ok(self.tok(Token::Percent, start, line))
            }
            b'#' => {
                self.pos += 1;
                Ok(self.tok(Token::Hash, start, line))
            }
            b'(' => {
                self.pos += 1;
                Ok(self.tok(Token::LParen, start, line))
            }
            b')' => {
                self.pos += 1;
                Ok(self.tok(Token::RParen, start, line))
            }
            b'{' => {
                self.pos += 1;
                Ok(self.tok(Token::LBrace, start, line))
            }
            b'}' => {
                self.pos += 1;
                Ok(self.tok(Token::RBrace, start, line))
            }
            b']' => {
                self.pos += 1;
                Ok(self.tok(Token::RBracket, start, line))
            }
            b';' => {
                self.pos += 1;
                Ok(self.tok(Token::Semicolon, start, line))
            }
            b':' => {
                self.pos += 1;
                Ok(self.tok(Token::Colon, start, line))
            }
            b',' => {
                self.pos += 1;
                Ok(self.tok(Token::Comma, start, line))
            }

            b'/' => {
                if self.peek() == b'/' {
                    self.pos += 2;
                    Ok(self.tok(Token::SlashSlash, start, line))
                } else {
                    self.pos += 1;
                    Err(ParseError::SingleSlash {
                        span: self.span_from(start, line),
                    })
                }
            }

            b'=' => {
                if self.peek() == b'=' {
                    self.pos += 2;
                    Ok(self.tok(Token::Eq, start, line))
                } else {
                    self.pos += 1;
                    Ok(self.tok(Token::Assign, start, line))
                }
            }

            b'~' => {
                if self.peek() == b'=' {
                    self.pos += 2;
                    Ok(self.tok(Token::TildeEq, start, line))
                } else {
                    self.pos += 1;
                    Err(ParseError::UnexpectedChar {
                        span: self.span_from(start, line),
                        ch: '~',
                    })
                }
            }

            b'<' => {
                if self.peek() == b'=' {
                    self.pos += 2;
                    Ok(self.tok(Token::LtEq, start, line))
                } else {
                    self.pos += 1;
                    Ok(self.tok(Token::Lt, start, line))
                }
            }

            b'>' => {
                if self.peek() == b'=' {
                    self.pos += 2;
                    Ok(self.tok(Token::GtEq, start, line))
                } else {
                    self.pos += 1;
                    Ok(self.tok(Token::Gt, start, line))
                }
            }

            b'.' => {
                if self.peek() == b'.' {
                    if self.pos + 2 < self.src.len() && self.src[self.pos + 2] == b'.' {
                        self.pos += 3;
                        Ok(self.tok(Token::DotDotDot, start, line))
                    } else {
                        self.pos += 2;
                        Ok(self.tok(Token::DotDot, start, line))
                    }
                } else if self.peek().is_ascii_digit() {
                    self.pos += 1;
                    Err(ParseError::FloatLiteral {
                        span: self.span_from(start, line),
                    })
                } else {
                    self.pos += 1;
                    Ok(self.tok(Token::Dot, start, line))
                }
            }

            b'[' => {
                // Long string or plain bracket
                if let Some(level) = self.count_long_bracket_open() {
                    let bytes = self.read_long_string_collect(level, start, line)?;
                    Ok(SpannedToken {
                        token: Token::StringLit(bytes),
                        span: self.span_from(start, line),
                    })
                } else {
                    self.pos += 1;
                    Ok(self.tok(Token::LBracket, start, line))
                }
            }

            b'"' | b'\'' => self.read_short_string(start, line),

            b'0'..=b'9' => self.read_number(start, line),

            b'a'..=b'z' | b'A'..=b'Z' | b'_' => self.read_ident_or_keyword(start, line),

            other => {
                self.pos += 1;
                Err(ParseError::UnexpectedChar {
                    span: self.span_from(start, line),
                    ch: other as char,
                })
            }
        }
    }

    fn tok(&self, token: Token, start: usize, line: u32) -> SpannedToken {
        SpannedToken {
            token,
            span: Span::new(start, self.pos, line),
        }
    }

    // --- Number lexing ---

    fn read_number(&mut self, start: usize, line: u32) -> Result<SpannedToken, ParseError> {
        // Hex?
        if self.cur() == b'0' && (self.peek() == b'x' || self.peek() == b'X') {
            self.pos += 2;
            let hex_start = self.pos;
            while self.pos < self.src.len() && self.src[self.pos].is_ascii_hexdigit() {
                self.pos += 1;
            }
            // Check for float-like suffix
            if self.pos < self.src.len() && matches!(self.src[self.pos], b'.' | b'p' | b'P') {
                self.pos += 1;
                return Err(ParseError::FloatLiteral {
                    span: self.span_from(start, line),
                });
            }
            let hex_str = core::str::from_utf8(&self.src[hex_start..self.pos]).unwrap();
            if hex_str.is_empty() {
                return Err(ParseError::UnexpectedToken {
                    span: self.span_from(start, line),
                    expected: "hex digits after 0x",
                    got: "nothing".into(),
                });
            }
            let val = u64::from_str_radix(hex_str, 16)
                .ok()
                .and_then(|v| i64::try_from(v).ok())
                .or_else(|| {
                    // Allow values that fit in i64 via bit reinterpretation (e.g. 0xFFFFFFFFFFFFFFFF)
                    u64::from_str_radix(hex_str, 16).ok().map(|v| v as i64)
                });
            let val = val.ok_or_else(|| ParseError::IntegerOverflow {
                span: self.span_from(start, line),
            })?;
            return Ok(SpannedToken {
                token: Token::Integer(val),
                span: self.span_from(start, line),
            });
        }

        // Decimal
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        // Float check: `.digit` or `e`/`E`
        if self.pos < self.src.len() && matches!(self.src[self.pos], b'.' | b'e' | b'E') {
            self.pos += 1;
            return Err(ParseError::FloatLiteral {
                span: self.span_from(start, line),
            });
        }

        let text = core::str::from_utf8(&self.src[start..self.pos]).unwrap();
        let val: i64 = text.parse().map_err(|_| ParseError::IntegerOverflow {
            span: self.span_from(start, line),
        })?;
        Ok(SpannedToken {
            token: Token::Integer(val),
            span: self.span_from(start, line),
        })
    }

    // --- Short string lexing ---

    fn read_short_string(&mut self, start: usize, line: u32) -> Result<SpannedToken, ParseError> {
        let quote = self.cur();
        self.pos += 1; // consume opening quote

        let mut buf = Vec::new();
        loop {
            if self.pos >= self.src.len() || self.cur() == b'\n' {
                return Err(ParseError::UnterminatedString {
                    span: self.span_from(start, line),
                });
            }
            let c = self.cur();
            if c == quote {
                self.pos += 1;
                break;
            }
            if c == b'\\' {
                self.pos += 1;
                let esc_byte = self.read_escape(start, line)?;
                buf.push(esc_byte);
            } else {
                buf.push(c);
                self.pos += 1;
            }
        }
        if buf.len() > MAX_STRING_LEN {
            return Err(ParseError::StringTooLong {
                span: self.span_from(start, line),
            });
        }
        Ok(SpannedToken {
            token: Token::StringLit(buf),
            span: self.span_from(start, line),
        })
    }

    fn read_escape(&mut self, start: usize, line: u32) -> Result<u8, ParseError> {
        if self.pos >= self.src.len() {
            return Err(ParseError::BadEscape {
                span: self.span_from(start, line),
            });
        }
        let esc_line = self.line;
        let esc_start = self.pos;
        let c = self.advance();
        match c {
            b'\\' => Ok(b'\\'),
            b'"' => Ok(b'"'),
            b'\'' => Ok(b'\''),
            b'n' => Ok(b'\n'),
            b'r' => Ok(b'\r'),
            b't' => Ok(b'\t'),
            b'0' => Ok(0),
            b'a' => Ok(7),  // bell
            b'b' => Ok(8),  // backspace
            b'f' => Ok(12), // form feed
            b'v' => Ok(11), // vertical tab
            b'\n' | b'\r' => Ok(b'\n'),
            b'x' => {
                // \xNN — exactly 2 hex digits
                let mut val: u32 = 0;
                for _ in 0..2 {
                    if self.pos >= self.src.len() || !self.cur().is_ascii_hexdigit() {
                        return Err(ParseError::BadEscape {
                            span: Span::new(esc_start, self.pos, esc_line),
                        });
                    }
                    val = val * 16 + hex_digit_val(self.cur()) as u32;
                    self.pos += 1;
                }
                Ok(val as u8)
            }
            b'0'..=b'9' => {
                // Already consumed the first digit in `c`
                // Decimal escape: 1–3 digits, value 0–255
                let mut val = (c - b'0') as u32;
                let mut count = 1;
                while count < 3 && self.pos < self.src.len() && self.cur().is_ascii_digit() {
                    val = val * 10 + (self.cur() - b'0') as u32;
                    self.pos += 1;
                    count += 1;
                }
                if val > 255 {
                    return Err(ParseError::BadEscape {
                        span: Span::new(esc_start, self.pos, esc_line),
                    });
                }
                Ok(val as u8)
            }
            _ => Err(ParseError::BadEscape {
                span: Span::new(esc_start, self.pos, esc_line),
            }),
        }
    }

    // --- Long string collecting ---

    fn read_long_string_collect(
        &mut self,
        level: usize,
        start: usize,
        line: u32,
    ) -> Result<Vec<u8>, ParseError> {
        self.consume_long_bracket_open(level);
        // Skip initial newline
        if self.pos < self.src.len() && self.cur() == b'\n' {
            self.advance();
        } else if self.pos + 1 < self.src.len() && self.cur() == b'\r' && self.peek() == b'\n' {
            self.advance();
            self.advance();
        }

        let mut buf = Vec::new();
        loop {
            if self.pos >= self.src.len() {
                return Err(ParseError::UnterminatedString {
                    span: Span::new(start, self.pos, line),
                });
            }
            let c = self.advance();
            if c == b']' {
                let mut eq = 0usize;
                while self.pos < self.src.len() && self.src[self.pos] == b'=' {
                    eq += 1;
                    self.pos += 1;
                }
                if eq == level && self.pos < self.src.len() && self.src[self.pos] == b']' {
                    self.pos += 1;
                    if buf.len() > MAX_STRING_LEN {
                        return Err(ParseError::StringTooLong {
                            span: Span::new(start, self.pos, line),
                        });
                    }
                    return Ok(buf);
                } else {
                    buf.push(b']');
                    for _ in 0..eq {
                        buf.push(b'=');
                    }
                }
            } else {
                buf.push(c);
            }
        }
    }

    // --- Identifier / keyword ---

    fn read_ident_or_keyword(
        &mut self,
        start: usize,
        line: u32,
    ) -> Result<SpannedToken, ParseError> {
        while self.pos < self.src.len()
            && (self.src[self.pos].is_ascii_alphanumeric() || self.src[self.pos] == b'_')
        {
            self.pos += 1;
        }
        let text = core::str::from_utf8(&self.src[start..self.pos]).unwrap();
        let token = match text {
            "and" => Token::KwAnd,
            "break" => Token::KwBreak,
            "do" => Token::KwDo,
            "else" => Token::KwElse,
            "elseif" => Token::KwElseif,
            "end" => Token::KwEnd,
            "false" => Token::KwFalse,
            "for" => Token::KwFor,
            "function" => Token::KwFunction,
            "if" => Token::KwIf,
            "in" => Token::KwIn,
            "local" => Token::KwLocal,
            "nil" => Token::KwNil,
            "not" => Token::KwNot,
            "or" => Token::KwOr,
            "return" => Token::KwReturn,
            "then" => Token::KwThen,
            "true" => Token::KwTrue,
            "while" => Token::KwWhile,
            _ => Token::Ident(text.to_string()),
        };
        Ok(SpannedToken {
            token,
            span: self.span_from(start, line),
        })
    }
}

fn hex_digit_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(src: &str) -> Result<Vec<Token>, ParseError> {
        Lexer::new(src)
            .tokenize()
            .map(|v| v.into_iter().map(|t| t.token).collect())
    }

    fn lex_ok(src: &str) -> Vec<Token> {
        lex(src).expect("lexing should succeed")
    }

    #[test]
    fn empty_input() {
        assert_eq!(lex_ok(""), vec![Token::Eof]);
    }

    #[test]
    fn integer_zero() {
        assert_eq!(lex_ok("0"), vec![Token::Integer(0), Token::Eof]);
    }

    #[test]
    fn integer_positive() {
        assert_eq!(lex_ok("42"), vec![Token::Integer(42), Token::Eof]);
    }

    #[test]
    fn integer_hex() {
        assert_eq!(lex_ok("0xFF"), vec![Token::Integer(255), Token::Eof]);
        assert_eq!(lex_ok("0x10"), vec![Token::Integer(16), Token::Eof]);
    }

    #[test]
    fn float_literal_rejected() {
        assert!(matches!(lex("3.14"), Err(ParseError::FloatLiteral { .. })));
        assert!(matches!(lex("1e5"), Err(ParseError::FloatLiteral { .. })));
        assert!(matches!(lex(".5"), Err(ParseError::FloatLiteral { .. })));
    }

    #[test]
    fn integer_overflow_rejected() {
        // 2^63 overflows i64
        assert!(matches!(
            lex("9223372036854775808"),
            Err(ParseError::IntegerOverflow { .. })
        ));
    }

    #[test]
    fn string_basic_escape() {
        let toks = lex_ok(r#""hello\nworld""#);
        assert_eq!(toks[0], Token::StringLit(b"hello\nworld".to_vec()));
    }

    #[test]
    fn string_hex_escape() {
        let toks = lex_ok(r#""\x41""#);
        assert_eq!(toks[0], Token::StringLit(vec![0x41]));
    }

    #[test]
    fn string_decimal_escape() {
        let toks = lex_ok(r#""\97""#);
        assert_eq!(toks[0], Token::StringLit(vec![97]));
    }

    #[test]
    fn string_bad_escape() {
        assert!(matches!(lex(r#""\q""#), Err(ParseError::BadEscape { .. })));
    }

    #[test]
    fn long_string_no_escape_processing() {
        let toks = lex_ok("[[foo\\nbar]]");
        // raw bytes — no escape processing
        assert_eq!(toks[0], Token::StringLit(b"foo\\nbar".to_vec()));
    }

    #[test]
    fn line_comment_skipped() {
        let toks = lex_ok("42 -- this is a comment\n1");
        assert_eq!(
            toks,
            vec![Token::Integer(42), Token::Integer(1), Token::Eof]
        );
    }

    #[test]
    fn block_comment_skipped() {
        let toks = lex_ok("1 --[[ multi\nline ]] 2");
        assert_eq!(toks, vec![Token::Integer(1), Token::Integer(2), Token::Eof]);
    }

    #[test]
    fn single_slash_rejected() {
        assert!(matches!(lex("1 / 2"), Err(ParseError::SingleSlash { .. })));
    }

    #[test]
    fn floor_division_ok() {
        assert_eq!(lex_ok("//"), vec![Token::SlashSlash, Token::Eof]);
    }

    #[test]
    fn tilde_eq() {
        assert_eq!(lex_ok("~="), vec![Token::TildeEq, Token::Eof]);
    }

    #[test]
    fn tilde_alone_rejected() {
        assert!(matches!(
            lex("~"),
            Err(ParseError::UnexpectedChar { ch: '~', .. })
        ));
    }

    #[test]
    fn keywords_recognized() {
        let src = "local function end if then else while for return break do in";
        let toks = lex_ok(src);
        assert_eq!(toks[0], Token::KwLocal);
        assert_eq!(toks[1], Token::KwFunction);
        assert_eq!(toks[2], Token::KwEnd);
        assert_eq!(toks[3], Token::KwIf);
    }

    #[test]
    fn tool_is_ident_not_keyword() {
        let toks = lex_ok("tool");
        assert_eq!(toks[0], Token::Ident("tool".into()));
    }

    #[test]
    fn string_too_long() {
        let big: String = "\"".to_string() + &"a".repeat(65537) + "\"";
        assert!(matches!(lex(&big), Err(ParseError::StringTooLong { .. })));
    }

    #[test]
    fn dotdot_vs_dot() {
        assert_eq!(lex_ok(".."), vec![Token::DotDot, Token::Eof]);
        assert_eq!(lex_ok("."), vec![Token::Dot, Token::Eof]);
    }

    #[test]
    fn dotdotdot() {
        assert_eq!(lex_ok("..."), vec![Token::DotDotDot, Token::Eof]);
    }

    #[test]
    fn comparison_operators() {
        let toks = lex_ok("== ~= < <= > >=");
        assert_eq!(toks[0], Token::Eq);
        assert_eq!(toks[1], Token::TildeEq);
        assert_eq!(toks[2], Token::Lt);
        assert_eq!(toks[3], Token::LtEq);
        assert_eq!(toks[4], Token::Gt);
        assert_eq!(toks[5], Token::GtEq);
    }

    #[test]
    fn string_single_quote() {
        let toks = lex_ok("'hello'");
        assert_eq!(toks[0], Token::StringLit(b"hello".to_vec()));
    }

    #[test]
    fn nested_long_string() {
        let toks = lex_ok("[==[hello]==]");
        assert_eq!(toks[0], Token::StringLit(b"hello".to_vec()));
    }
}
