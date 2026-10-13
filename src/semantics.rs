use std::collections::{HashMap, HashSet};
use crate::ast::*;
use crate::source::{Diagnostic, Span};
use crate::types::Type;

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub ty: Type,
    pub is_mut: bool,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Scope {
    symbols: HashMap<String, Symbol>,
}

impl Scope {
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
        }
    }
}

pub struct SymbolTable {
    scopes: Vec<Scope>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            scopes: vec![Scope::new()],
        }
    }

    pub fn enter_scope(&mut self) {
        self.scopes.push(Scope::new());
    }

    pub fn exit_scope(&mut self) {
        self.scopes.pop();
    }

    pub fn insert(&mut self, symbol: Symbol) -> Result<(), Diagnostic> {
        let current = self.scopes.last_mut().unwrap();
        if let Some(existing) = current.symbols.get(&symbol.name) {
            return Err(Diagnostic::error(
                format!("Identifier '{}' already declared in this scope", symbol.name),
                symbol.span,
            )
            .with_hint(format!("Previous declaration was at {}", existing.span)));
        }
        current.symbols.insert(symbol.name.clone(), symbol);
        Ok(())
    }

    pub fn lookup(&self, name: &str) -> Option<&Symbol> {
        for scope in self.scopes.iter().rev() {
            if let Some(sym) = scope.symbols.get(name) {
                return Some(sym);
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub name: String,
    pub params: Vec<Type>,
    pub return_type: Type,
    pub required_capability: Option<&'static str>,
}

pub struct SemanticAnalyzer {
    symbols: SymbolTable,
    functions: HashMap<String, FunctionSignature>,
    declared_capabilities: HashSet<String>,
    current_fn_return: Type,
}

impl SemanticAnalyzer {
    pub fn new() -> Self {
        let mut functions = HashMap::new();
        // Register built-in host functions with their capability requirements
        functions.insert(
            "print_i32".to_string(),
            FunctionSignature {
                name: "print_i32".to_string(),
                params: vec![Type::I32],
                return_type: Type::Void,
                required_capability: Some("console.write"),
            },
        );
        functions.insert(
            "print_bool".to_string(),
            FunctionSignature {
                name: "print_bool".to_string(),
                params: vec![Type::Bool],
                return_type: Type::Void,
                required_capability: Some("console.write"),
            },
        );
        functions.insert(
            "read_i32".to_string(),
            FunctionSignature {
                name: "read_i32".to_string(),
                params: vec![],
                return_type: Type::I32,
                required_capability: None, // untrusted source
            },
        );
        functions.insert(
            "sanitize_i32".to_string(),
            FunctionSignature {
                name: "sanitize_i32".to_string(),
                params: vec![Type::I32],
                return_type: Type::I32,
                required_capability: None,
            },
        );

        Self {
            symbols: SymbolTable::new(),
            functions,
            declared_capabilities: HashSet::new(),
            current_fn_return: Type::Void,
        }
    }

    pub fn analyze_program(&mut self, program: &Program) -> Result<(), Diagnostic> {
        // 1. Record declared capabilities
        for cap in &program.capabilities {
            self.declared_capabilities.insert(cap.name.clone());
        }

        // 2. Register all user-defined functions
        for f in &program.functions {
            if self.functions.contains_key(&f.name) {
                return Err(Diagnostic::error(
                    format!("Duplicate function definition '{}'", f.name),
                    f.span,
                ));
            }
            let param_types = f.params.iter().map(|p| p.ty).collect();
            self.functions.insert(
                f.name.clone(),
                FunctionSignature {
                    name: f.name.clone(),
                    params: param_types,
                    return_type: f.return_type,
                    required_capability: None,
                },
            );
        }

        // 3. Analyze function bodies
        for f in &program.functions {
            self.analyze_function(f)?;
        }

        Ok(())
    }

    fn analyze_function(&mut self, f: &FunctionDecl) -> Result<(), Diagnostic> {
        self.symbols.enter_scope();
        self.current_fn_return = f.return_type;

        for param in &f.params {
            self.symbols.insert(Symbol {
                name: param.name.clone(),
                ty: param.ty,
                is_mut: false,
                span: param.span,
            })?;
        }

        self.analyze_block(&f.body)?;

        self.symbols.exit_scope();
        Ok(())
    }

    fn analyze_block(&mut self, block: &Block) -> Result<(), Diagnostic> {
        self.symbols.enter_scope();
        for stmt in &block.statements {
            self.analyze_statement(stmt)?;
        }
        self.symbols.exit_scope();
        Ok(())
    }

    fn analyze_statement(&mut self, stmt: &Statement) -> Result<(), Diagnostic> {
        match stmt {
            Statement::Let {
                name,
                is_mut,
                ty,
                init,
                span,
            } => {
                let init_ty = self.check_expr(init)?;
                let final_ty = if let Some(annotated_ty) = ty {
                    if *annotated_ty != init_ty {
                        return Err(Diagnostic::error(
                            format!(
                                "Type mismatch in variable declaration '{}': expected {}, found {}",
                                name, annotated_ty, init_ty
                            ),
                            *span,
                        ));
                    }
                    *annotated_ty
                } else {
                    init_ty
                };

                self.symbols.insert(Symbol {
                    name: name.clone(),
                    ty: final_ty,
                    is_mut: *is_mut,
                    span: *span,
                })?;
                Ok(())
            }
            Statement::Assign { target, value, span } => {
                let sym = self.symbols.lookup(target).ok_or_else(|| {
                    Diagnostic::error(
                        format!("Cannot assign to undeclared variable '{}'", target),
                        *span,
                    )
                })?;

                if !sym.is_mut {
                    return Err(Diagnostic::error(
                        format!(
                            "Cannot reassign to immutable variable '{}'; declare it with 'let mut'",
                            target
                        ),
                        *span,
                    ));
                }

                let target_ty = sym.ty;
                let val_ty = self.check_expr(value)?;
                if target_ty != val_ty {
                    return Err(Diagnostic::error(
                        format!(
                            "Type mismatch in assignment to '{}': variable has type {}, but value has type {}",
                            target, target_ty, val_ty
                        ),
                        *span,
                    ));
                }
                Ok(())
            }
            Statement::If {
                cond,
                then_block,
                else_block,
                span,
            } => {
                let cond_ty = self.check_expr(cond)?;
                if cond_ty != Type::Bool {
                    return Err(Diagnostic::error(
                        format!("If condition must be of type bool, found {}", cond_ty),
                        *span,
                    ));
                }
                self.analyze_block(then_block)?;
                if let Some(eb) = else_block {
                    self.analyze_block(eb)?;
                }
                Ok(())
            }
            Statement::While { cond, body, span } => {
                let cond_ty = self.check_expr(cond)?;
                if cond_ty != Type::Bool {
                    return Err(Diagnostic::error(
                        format!("While condition must be of type bool, found {}", cond_ty),
                        *span,
                    ));
                }
                self.analyze_block(body)?;
                Ok(())
            }
            Statement::Return { value, span } => {
                let ret_ty = if let Some(expr) = value {
                    self.check_expr(expr)?
                } else {
                    Type::Void
                };

                if ret_ty != self.current_fn_return {
                    return Err(Diagnostic::error(
                        format!(
                            "Return type mismatch: expected {}, but returning {}",
                            self.current_fn_return, ret_ty
                        ),
                        *span,
                    ));
                }
                Ok(())
            }
            Statement::Expr(expr) => {
                self.check_expr(expr)?;
                Ok(())
            }
        }
    }

    pub fn check_expr(&self, expr: &Expr) -> Result<Type, Diagnostic> {
        match expr {
            Expr::Integer(_, _) => Ok(Type::I32),
            Expr::Boolean(_, _) => Ok(Type::Bool),
            Expr::Variable(name, span) => {
                let sym = self.symbols.lookup(name).ok_or_else(|| {
                    Diagnostic::error(format!("Undeclared identifier '{}'", name), *span)
                })?;
                Ok(sym.ty)
            }
            Expr::Binary { op, lhs, rhs, span } => {
                let l_ty = self.check_expr(lhs)?;
                let r_ty = self.check_expr(rhs)?;

                match op {
                    BinaryOp::Add
                    | BinaryOp::Sub
                    | BinaryOp::Mul
                    | BinaryOp::Div
                    | BinaryOp::Rem => {
                        if l_ty != Type::I32 || r_ty != Type::I32 {
                            return Err(Diagnostic::error(
                                format!(
                                    "Arithmetic operator {:?} requires i32 operands, found {} and {}",
                                    op, l_ty, r_ty
                                ),
                                *span,
                            ));
                        }
                        Ok(Type::I32)
                    }
                    BinaryOp::Lt | BinaryOp::Lte | BinaryOp::Gt | BinaryOp::Gte => {
                        if l_ty != Type::I32 || r_ty != Type::I32 {
                            return Err(Diagnostic::error(
                                format!(
                                    "Comparison operator {:?} requires i32 operands, found {} and {}",
                                    op, l_ty, r_ty
                                ),
                                *span,
                            ));
                        }
                        Ok(Type::Bool)
                    }
                    BinaryOp::Eq | BinaryOp::Neq => {
                        if l_ty != r_ty {
                            return Err(Diagnostic::error(
                                format!(
                                    "Equality operator {:?} requires matching operand types, found {} and {}",
                                    op, l_ty, r_ty
                                ),
                                *span,
                            ));
                        }
                        Ok(Type::Bool)
                    }
                    BinaryOp::And | BinaryOp::Or => {
                        if l_ty != Type::Bool || r_ty != Type::Bool {
                            return Err(Diagnostic::error(
                                format!(
                                    "Logical operator {:?} requires bool operands, found {} and {}",
                                    op, l_ty, r_ty
                                ),
                                *span,
                            ));
                        }
                        Ok(Type::Bool)
                    }
                }
            }
            Expr::Unary { op, expr, span } => {
                let inner_ty = self.check_expr(expr)?;
                match op {
                    UnaryOp::Neg => {
                        if inner_ty != Type::I32 {
                            return Err(Diagnostic::error(
                                format!("Unary negation '-' requires i32 operand, found {}", inner_ty),
                                *span,
                            ));
                        }
                        Ok(Type::I32)
                    }
                    UnaryOp::Not => {
                        if inner_ty != Type::Bool {
                            return Err(Diagnostic::error(
                                format!("Logical not '!' requires bool operand, found {}", inner_ty),
                                *span,
                            ));
                        }
                        Ok(Type::Bool)
                    }
                }
            }
            Expr::Call { callee, args, span } => {
                let sig = self.functions.get(callee).cloned().ok_or_else(|| {
                    Diagnostic::error(format!("Call to undefined function '{}'", callee), *span)
                })?;

                // Check capability requirements for privileged functions
                if let Some(required_cap) = sig.required_capability {
                    if !self.declared_capabilities.contains(required_cap) {
                        return Err(Diagnostic::error(
                            format!(
                                "Privileged host function '{}' requires capability '{}', which is not declared in module header",
                                callee, required_cap
                            ),
                            *span,
                        )
                        .with_hint(format!("Add 'requires {};' at the top of the module", required_cap)));
                    }
                }

                if args.len() != sig.params.len() {
                    return Err(Diagnostic::error(
                        format!(
                            "Function '{}' expects {} arguments, but received {}",
                            callee,
                            sig.params.len(),
                            args.len()
                        ),
                        *span,
                    ));
                }

                for (idx, (arg, &expected_ty)) in args.iter().zip(sig.params.iter()).enumerate() {
                    let actual_ty = self.check_expr(arg)?;
                    if actual_ty != expected_ty {
                        return Err(Diagnostic::error(
                            format!(
                                "Argument {} to function '{}' type mismatch: expected {}, found {}",
                                idx + 1,
                                callee,
                                expected_ty,
                                actual_ty
                            ),
                            arg.span(),
                        ));
                    }
                }

                Ok(sig.return_type)
            }
            Expr::Block(block) => {
                // Block expression evaluation
                let mut last_ty = Type::Void;
                for stmt in &block.statements {
                    if let Statement::Expr(e) = stmt {
                        last_ty = self.check_expr(e)?;
                    } else {
                        last_ty = Type::Void;
                    }
                }
                Ok(last_ty)
            }
        }
    }
}
