use crate::ast::*;
use crate::lexer::{Token, TokenKind};
use crate::source::Diagnostic;
use crate::types::Type;

pub struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, cursor: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens
            .get(self.cursor)
            .unwrap_or_else(|| self.tokens.last().unwrap())
    }

    fn peek_kind(&self) -> &TokenKind {
        &self.peek().kind
    }

    fn advance(&mut self) -> Token {
        let tok = self.peek().clone();
        if self.cursor < self.tokens.len() {
            self.cursor += 1;
        }
        tok
    }

    fn check(&self, kind: &TokenKind) -> bool {
        self.peek_kind() == kind
    }

    fn match_token(&mut self, kind: &TokenKind) -> bool {
        if self.check(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, kind: TokenKind, context: &str) -> Result<Token, Diagnostic> {
        if self.check(&kind) {
            Ok(self.advance())
        } else {
            let actual = self.peek();
            Err(Diagnostic::error(
                format!(
                    "Expected {:?} {}, but found {:?}",
                    kind, context, actual.kind
                ),
                actual.span,
            ))
        }
    }

    pub fn parse_program(&mut self) -> Result<Program, Diagnostic> {
        let mod_tok = self.expect(TokenKind::Module, "at start of file")?;
        let mod_ident = self.expect_ident("for module name")?;
        self.expect(TokenKind::Semi, "after module declaration")?;

        let module_span = mod_tok.span.merge(mod_ident.span);
        let mut capabilities = Vec::new();

        while self.check(&TokenKind::Requires) {
            let req_tok = self.advance();
            let cap_name = self.parse_capability_path()?;
            let semi = self.expect(TokenKind::Semi, "after capability declaration")?;
            capabilities.push(CapabilityDecl {
                name: cap_name,
                span: req_tok.span.merge(semi.span),
            });
        }

        let mut functions = Vec::new();
        while !self.check(&TokenKind::Eof) {
            functions.push(self.parse_function()?);
        }

        Ok(Program {
            module_name: match mod_ident.kind {
                TokenKind::Ident(s) => s,
                _ => unreachable!(),
            },
            module_span,
            capabilities,
            functions,
        })
    }

    fn expect_ident(&mut self, context: &str) -> Result<Token, Diagnostic> {
        let tok = self.peek();
        match &tok.kind {
            TokenKind::Ident(_) => Ok(self.advance()),
            _ => Err(Diagnostic::error(
                format!("Expected identifier {}, found {:?}", context, tok.kind),
                tok.span,
            )),
        }
    }

    fn parse_capability_path(&mut self) -> Result<String, Diagnostic> {
        let mut parts = Vec::new();
        let first = self.expect_ident("in capability name")?;
        if let TokenKind::Ident(s) = first.kind {
            parts.push(s);
        }

        while self.match_token(&TokenKind::Dot) {
            let next = self.expect_ident("after '.' in capability name")?;
            if let TokenKind::Ident(s) = next.kind {
                parts.push(s);
            }
        }

        Ok(parts.join("."))
    }

    fn parse_type(&mut self) -> Result<Type, Diagnostic> {
        let tok = self.peek();
        match &tok.kind {
            TokenKind::I32 => {
                self.advance();
                Ok(Type::I32)
            }
            TokenKind::Bool => {
                self.advance();
                Ok(Type::Bool)
            }
            TokenKind::Ident(s) if s == "void" => {
                self.advance();
                Ok(Type::Void)
            }
            _ => Err(Diagnostic::error(
                format!("Expected type (i32, bool, void), found {:?}", tok.kind),
                tok.span,
            )),
        }
    }

    fn parse_function(&mut self) -> Result<FunctionDecl, Diagnostic> {
        let fn_tok = self.expect(TokenKind::Fn, "for function declaration")?;
        let name_tok = self.expect_ident("for function name")?;
        let fn_name = match name_tok.kind {
            TokenKind::Ident(s) => s,
            _ => unreachable!(),
        };

        self.expect(TokenKind::LParen, "after function name")?;
        let mut params = Vec::new();
        if !self.check(&TokenKind::RParen) {
            loop {
                let p_name_tok = self.expect_ident("for parameter name")?;
                let p_name = match p_name_tok.kind {
                    TokenKind::Ident(s) => s,
                    _ => unreachable!(),
                };
                self.expect(TokenKind::Colon, "after parameter name")?;
                let p_type = self.parse_type()?;
                params.push(Param {
                    name: p_name,
                    ty: p_type,
                    span: p_name_tok.span,
                });

                if !self.match_token(&TokenKind::Comma) {
                    break;
                }
            }
        }
        self.expect(TokenKind::RParen, "after function parameters")?;

        let return_type = if self.match_token(&TokenKind::Arrow) {
            self.parse_type()?
        } else {
            Type::Void
        };

        let body = self.parse_block()?;
        let span = fn_tok.span.merge(body.span);

        Ok(FunctionDecl {
            name: fn_name,
            params,
            return_type,
            body,
            span,
        })
    }

    fn parse_block(&mut self) -> Result<Block, Diagnostic> {
        let lbrace = self.expect(TokenKind::LBrace, "at start of block")?;
        let mut statements = Vec::new();

        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            statements.push(self.parse_statement()?);
        }

        let rbrace = self.expect(TokenKind::RBrace, "at end of block")?;
        Ok(Block {
            statements,
            span: lbrace.span.merge(rbrace.span),
        })
    }

    fn parse_statement(&mut self) -> Result<Statement, Diagnostic> {
        match self.peek_kind() {
            TokenKind::Let => self.parse_let_statement(),
            TokenKind::If => self.parse_if_statement(),
            TokenKind::While => self.parse_while_statement(),
            TokenKind::Return => self.parse_return_statement(),
            TokenKind::Ident(_) if self.is_assignment_ahead() => self.parse_assign_statement(),
            _ => {
                let expr = self.parse_expression()?;
                self.expect(TokenKind::Semi, "after expression statement")?;
                Ok(Statement::Expr(expr))
            }
        }
    }

    fn is_assignment_ahead(&self) -> bool {
        if self.cursor + 1 < self.tokens.len() {
            matches!(self.tokens[self.cursor + 1].kind, TokenKind::Assign)
        } else {
            false
        }
    }

    fn parse_let_statement(&mut self) -> Result<Statement, Diagnostic> {
        let let_tok = self.advance();
        let is_mut = self.match_token(&TokenKind::Mut);
        let name_tok = self.expect_ident("for variable name in let statement")?;
        let var_name = match name_tok.kind {
            TokenKind::Ident(s) => s,
            _ => unreachable!(),
        };

        let ty = if self.match_token(&TokenKind::Colon) {
            Some(self.parse_type()?)
        } else {
            None
        };

        self.expect(TokenKind::Assign, "in let binding")?;
        let init = self.parse_expression()?;
        let semi = self.expect(TokenKind::Semi, "at end of let statement")?;

        Ok(Statement::Let {
            name: var_name,
            is_mut,
            ty,
            init,
            span: let_tok.span.merge(semi.span),
        })
    }

    fn parse_assign_statement(&mut self) -> Result<Statement, Diagnostic> {
        let name_tok = self.expect_ident("for assignment target")?;
        let target = match name_tok.kind {
            TokenKind::Ident(s) => s,
            _ => unreachable!(),
        };
        self.expect(TokenKind::Assign, "in assignment")?;
        let value = self.parse_expression()?;
        let semi = self.expect(TokenKind::Semi, "after assignment statement")?;

        Ok(Statement::Assign {
            target,
            value,
            span: name_tok.span.merge(semi.span),
        })
    }

    fn parse_if_statement(&mut self) -> Result<Statement, Diagnostic> {
        let if_tok = self.advance();
        let cond = self.parse_expression()?;
        let then_block = self.parse_block()?;

        let (else_block, end_span) = if self.match_token(&TokenKind::Else) {
            if self.check(&TokenKind::If) {
                // else if -> single statement block
                let nested_if = self.parse_if_statement()?;
                let nested_span = match &nested_if {
                    Statement::If { span, .. } => *span,
                    _ => unreachable!(),
                };
                let blk = Block {
                    statements: vec![nested_if],
                    span: nested_span,
                };
                (Some(blk), nested_span)
            } else {
                let blk = self.parse_block()?;
                let blk_span = blk.span;
                (Some(blk), blk_span)
            }
        } else {
            (None, then_block.span)
        };

        Ok(Statement::If {
            cond,
            then_block,
            else_block,
            span: if_tok.span.merge(end_span),
        })
    }

    fn parse_while_statement(&mut self) -> Result<Statement, Diagnostic> {
        let while_tok = self.advance();
        let cond = self.parse_expression()?;
        let body = self.parse_block()?;
        let span = while_tok.span.merge(body.span);

        Ok(Statement::While { cond, body, span })
    }

    fn parse_return_statement(&mut self) -> Result<Statement, Diagnostic> {
        let ret_tok = self.advance();
        if self.match_token(&TokenKind::Semi) {
            Ok(Statement::Return {
                value: None,
                span: ret_tok.span,
            })
        } else {
            let val = self.parse_expression()?;
            let semi = self.expect(TokenKind::Semi, "after return statement")?;
            Ok(Statement::Return {
                value: Some(val),
                span: ret_tok.span.merge(semi.span),
            })
        }
    }

    pub fn parse_expression(&mut self) -> Result<Expr, Diagnostic> {
        self.parse_logical_or()
    }

    fn parse_logical_or(&mut self) -> Result<Expr, Diagnostic> {
        let mut lhs = self.parse_logical_and()?;
        while self.match_token(&TokenKind::PipePipe) {
            let rhs = self.parse_logical_and()?;
            let span = lhs.span().merge(rhs.span());
            lhs = Expr::Binary {
                op: BinaryOp::Or,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        Ok(lhs)
    }

    fn parse_logical_and(&mut self) -> Result<Expr, Diagnostic> {
        let mut lhs = self.parse_equality()?;
        while self.match_token(&TokenKind::AmpAmp) {
            let rhs = self.parse_equality()?;
            let span = lhs.span().merge(rhs.span());
            lhs = Expr::Binary {
                op: BinaryOp::And,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        Ok(lhs)
    }

    fn parse_equality(&mut self) -> Result<Expr, Diagnostic> {
        let mut lhs = self.parse_relational()?;
        while let Some(op) = match self.peek_kind() {
            TokenKind::EqEq => Some(BinaryOp::Eq),
            TokenKind::BangEq => Some(BinaryOp::Neq),
            _ => None,
        } {
            self.advance();
            let rhs = self.parse_relational()?;
            let span = lhs.span().merge(rhs.span());
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        Ok(lhs)
    }

    fn parse_relational(&mut self) -> Result<Expr, Diagnostic> {
        let mut lhs = self.parse_additive()?;
        while let Some(op) = match self.peek_kind() {
            TokenKind::Lt => Some(BinaryOp::Lt),
            TokenKind::LtEq => Some(BinaryOp::Lte),
            TokenKind::Gt => Some(BinaryOp::Gt),
            TokenKind::GtEq => Some(BinaryOp::Gte),
            _ => None,
        } {
            self.advance();
            let rhs = self.parse_additive()?;
            let span = lhs.span().merge(rhs.span());
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        Ok(lhs)
    }

    fn parse_additive(&mut self) -> Result<Expr, Diagnostic> {
        let mut lhs = self.parse_multiplicative()?;
        while let Some(op) = match self.peek_kind() {
            TokenKind::Plus => Some(BinaryOp::Add),
            TokenKind::Minus => Some(BinaryOp::Sub),
            _ => None,
        } {
            self.advance();
            let rhs = self.parse_multiplicative()?;
            let span = lhs.span().merge(rhs.span());
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        Ok(lhs)
    }

    fn parse_multiplicative(&mut self) -> Result<Expr, Diagnostic> {
        let mut lhs = self.parse_unary()?;
        while let Some(op) = match self.peek_kind() {
            TokenKind::Star => Some(BinaryOp::Mul),
            TokenKind::Slash => Some(BinaryOp::Div),
            TokenKind::Percent => Some(BinaryOp::Rem),
            _ => None,
        } {
            self.advance();
            let rhs = self.parse_unary()?;
            let span = lhs.span().merge(rhs.span());
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, Diagnostic> {
        if self.match_token(&TokenKind::Minus) {
            let tok_span = self.tokens[self.cursor - 1].span;
            let expr = self.parse_unary()?;
            let span = tok_span.merge(expr.span());
            Ok(Expr::Unary {
                op: UnaryOp::Neg,
                expr: Box::new(expr),
                span,
            })
        } else if self.match_token(&TokenKind::Bang) {
            let tok_span = self.tokens[self.cursor - 1].span;
            let expr = self.parse_unary()?;
            let span = tok_span.merge(expr.span());
            Ok(Expr::Unary {
                op: UnaryOp::Not,
                expr: Box::new(expr),
                span,
            })
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, Diagnostic> {
        let tok = self.peek().clone();
        match &tok.kind {
            TokenKind::IntLiteral(val) => {
                self.advance();
                Ok(Expr::Integer(*val, tok.span))
            }
            TokenKind::True => {
                self.advance();
                Ok(Expr::Boolean(true, tok.span))
            }
            TokenKind::False => {
                self.advance();
                Ok(Expr::Boolean(false, tok.span))
            }
            TokenKind::Ident(name) => {
                let name = name.clone();
                self.advance();
                if self.check(&TokenKind::LParen) {
                    // Function call
                    self.advance(); // consume '('
                    let mut args = Vec::new();
                    if !self.check(&TokenKind::RParen) {
                        loop {
                            args.push(self.parse_expression()?);
                            if !self.match_token(&TokenKind::Comma) {
                                break;
                            }
                        }
                    }
                    let rparen = self.expect(TokenKind::RParen, "after function arguments")?;
                    let span = tok.span.merge(rparen.span);
                    Ok(Expr::Call {
                        callee: name,
                        args,
                        span,
                    })
                } else {
                    Ok(Expr::Variable(name, tok.span))
                }
            }
            TokenKind::LParen => {
                self.advance();
                let expr = self.parse_expression()?;
                self.expect(TokenKind::RParen, "after parenthesized expression")?;
                Ok(expr)
            }
            _ => Err(Diagnostic::error(
                format!("Unexpected token {:?} in expression", tok.kind),
                tok.span,
            )),
        }
    }
}
