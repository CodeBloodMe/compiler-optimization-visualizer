use crate::source::{Diagnostic, Span};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    // Keywords
    Module,
    Requires,
    Fn,
    Let,
    Mut,
    If,
    Else,
    While,
    Return,
    True,
    False,
    I32,
    Bool,

    // Identifiers & Literals
    Ident(String),
    IntLiteral(i64),

    // Symbols & Operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,
    BangEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    AmpAmp,
    PipePipe,
    Bang,
    Assign,
    Arrow, // ->

    // Delimiters
    Semi,
    Colon,
    Comma,
    Dot,
    LParen,
    RParen,
    LBrace,
    RBrace,

    Eof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

pub struct Lexer<'a> {
    #[allow(dead_code)]
    source: &'a str,
    chars: Vec<(usize, char)>,
    cursor: usize,
    line: usize,
    col: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(source: &'a str) -> Self {
        let chars: Vec<(usize, char)> = source.char_indices().collect();
        Self {
            source,
            chars,
            cursor: 0,
            line: 1,
            col: 1,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.cursor).map(|&(_, ch)| ch)
    }

    fn peek_next(&self) -> Option<char> {
        self.chars.get(self.cursor + 1).map(|&(_, ch)| ch)
    }

    fn advance(&mut self) -> Option<char> {
        if self.cursor >= self.chars.len() {
            return None;
        }
        let (_, ch) = self.chars[self.cursor];
        self.cursor += 1;
        if ch == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(ch)
    }

    fn skip_whitespace_and_comments(&mut self) {
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() {
                self.advance();
            } else if ch == '/' && self.peek_next() == Some('/') {
                // Single line comment
                while let Some(c) = self.peek() {
                    if c == '\n' {
                        break;
                    }
                    self.advance();
                }
            } else {
                break;
            }
        }
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, Diagnostic> {
        let mut tokens = Vec::new();

        loop {
            self.skip_whitespace_and_comments();

            let start_line = self.line;
            let start_col = self.col;

            let Some(ch) = self.peek() else {
                tokens.push(Token {
                    kind: TokenKind::Eof,
                    span: Span::point(self.line, self.col),
                });
                break;
            };

            let span_for = |end_line: usize, end_col: usize| {
                Span::new(start_line, start_col, end_line, end_col)
            };

            // Two-character and one-character symbols
            match ch {
                '+' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Plus,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                '-' => {
                    self.advance();
                    if self.peek() == Some('>') {
                        self.advance();
                        tokens.push(Token {
                            kind: TokenKind::Arrow,
                            span: span_for(self.line, self.col - 1),
                        });
                    } else {
                        tokens.push(Token {
                            kind: TokenKind::Minus,
                            span: span_for(self.line, self.col - 1),
                        });
                    }
                }
                '*' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Star,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                '/' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Slash,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                '%' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Percent,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                '=' => {
                    self.advance();
                    if self.peek() == Some('=') {
                        self.advance();
                        tokens.push(Token {
                            kind: TokenKind::EqEq,
                            span: span_for(self.line, self.col - 1),
                        });
                    } else {
                        tokens.push(Token {
                            kind: TokenKind::Assign,
                            span: span_for(self.line, self.col - 1),
                        });
                    }
                }
                '!' => {
                    self.advance();
                    if self.peek() == Some('=') {
                        self.advance();
                        tokens.push(Token {
                            kind: TokenKind::BangEq,
                            span: span_for(self.line, self.col - 1),
                        });
                    } else {
                        tokens.push(Token {
                            kind: TokenKind::Bang,
                            span: span_for(self.line, self.col - 1),
                        });
                    }
                }
                '<' => {
                    self.advance();
                    if self.peek() == Some('=') {
                        self.advance();
                        tokens.push(Token {
                            kind: TokenKind::LtEq,
                            span: span_for(self.line, self.col - 1),
                        });
                    } else {
                        tokens.push(Token {
                            kind: TokenKind::Lt,
                            span: span_for(self.line, self.col - 1),
                        });
                    }
                }
                '>' => {
                    self.advance();
                    if self.peek() == Some('=') {
                        self.advance();
                        tokens.push(Token {
                            kind: TokenKind::GtEq,
                            span: span_for(self.line, self.col - 1),
                        });
                    } else {
                        tokens.push(Token {
                            kind: TokenKind::Gt,
                            span: span_for(self.line, self.col - 1),
                        });
                    }
                }
                '&' => {
                    self.advance();
                    if self.peek() == Some('&') {
                        self.advance();
                        tokens.push(Token {
                            kind: TokenKind::AmpAmp,
                            span: span_for(self.line, self.col - 1),
                        });
                    } else {
                        return Err(Diagnostic::error(
                            "Unexpected character '&', expected '&&'",
                            span_for(self.line, self.col - 1),
                        ));
                    }
                }
                '|' => {
                    self.advance();
                    if self.peek() == Some('|') {
                        self.advance();
                        tokens.push(Token {
                            kind: TokenKind::PipePipe,
                            span: span_for(self.line, self.col - 1),
                        });
                    } else {
                        return Err(Diagnostic::error(
                            "Unexpected character '|', expected '||'",
                            span_for(self.line, self.col - 1),
                        ));
                    }
                }
                ';' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Semi,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                ':' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Colon,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                ',' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Comma,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                '.' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Dot,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                '(' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::LParen,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                ')' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::RParen,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                '{' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::LBrace,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                '}' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::RBrace,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                _ if ch.is_ascii_digit() => {
                    let mut num_str = String::new();
                    while let Some(d) = self.peek() {
                        if d.is_ascii_digit() {
                            num_str.push(d);
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    let val: i64 = num_str.parse().map_err(|_| {
                        Diagnostic::error(
                            format!("Integer literal '{}' out of range", num_str),
                            span_for(self.line, self.col - 1),
                        )
                    })?;
                    if val > 2147483648 {
                        return Err(Diagnostic::error(
                            format!(
                                "Integer literal '{}' out of range for i32 (exceeds maximum magnitude 2147483648)",
                                num_str
                            ),
                            span_for(self.line, self.col - 1),
                        ));
                    }
                    tokens.push(Token {
                        kind: TokenKind::IntLiteral(val),
                        span: span_for(self.line, self.col - 1),
                    });
                }
                _ if ch.is_alphabetic() || ch == '_' => {
                    let mut ident_str = String::new();
                    while let Some(c) = self.peek() {
                        if c.is_alphanumeric() || c == '_' {
                            ident_str.push(c);
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    let kind = match ident_str.as_str() {
                        "module" => TokenKind::Module,
                        "requires" => TokenKind::Requires,
                        "fn" => TokenKind::Fn,
                        "let" => TokenKind::Let,
                        "mut" => TokenKind::Mut,
                        "if" => TokenKind::If,
                        "else" => TokenKind::Else,
                        "while" => TokenKind::While,
                        "return" => TokenKind::Return,
                        "true" => TokenKind::True,
                        "false" => TokenKind::False,
                        "i32" => TokenKind::I32,
                        "bool" => TokenKind::Bool,
                        _ => TokenKind::Ident(ident_str),
                    };
                    tokens.push(Token {
                        kind,
                        span: span_for(self.line, self.col - 1),
                    });
                }
                _ => {
                    let bad_char = self.advance().unwrap();
                    return Err(Diagnostic::error(
                        format!("Unexpected character '{}'", bad_char),
                        span_for(self.line, self.col - 1),
                    ));
                }
            }
        }

        Ok(tokens)
    }
}
