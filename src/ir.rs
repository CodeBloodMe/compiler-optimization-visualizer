use crate::ast::*;
use crate::source::{Diagnostic, Span};
use crate::types::Type;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IrType {
    I32,
    Bool,
    Void,
}

impl From<Type> for IrType {
    fn from(t: Type) -> Self {
        match t {
            Type::I32 => IrType::I32,
            Type::Bool => IrType::Bool,
            Type::Void => IrType::Void,
        }
    }
}

impl fmt::Display for IrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrType::I32 => write!(f, "i32"),
            IrType::Bool => write!(f, "bool"),
            IrType::Void => write!(f, "void"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IrOperand {
    ConstI32(i32),
    ConstBool(bool),
    Local(usize), // local variable index
    Temp(usize),  // temporary value / virtual register
}

impl fmt::Display for IrOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrOperand::ConstI32(v) => write!(f, "{}", v),
            IrOperand::ConstBool(b) => write!(f, "{}", b),
            IrOperand::Local(id) => write!(f, "loc_{}", id),
            IrOperand::Temp(id) => write!(f, "t_{}", id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrBinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrUnaryOp {
    Neg,
    Not,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IrInst {
    Assign {
        dest: IrOperand,
        src: IrOperand,
    },
    Binary {
        dest: IrOperand,
        op: IrBinaryOp,
        lhs: IrOperand,
        rhs: IrOperand,
    },
    Unary {
        dest: IrOperand,
        op: IrUnaryOp,
        operand: IrOperand,
    },
    Call {
        dest: Option<IrOperand>,
        callee: String,
        args: Vec<IrOperand>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum IrTerminator {
    Return(Option<IrOperand>),
    Jump(usize),
    Branch {
        cond: IrOperand,
        then_block: usize,
        else_block: usize,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct BasicBlock {
    pub id: usize,
    pub label: String,
    pub instructions: Vec<IrInst>,
    pub terminator: IrTerminator,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IrFunction {
    pub name: String,
    pub params: Vec<(String, IrType)>,
    pub return_type: IrType,
    pub locals: Vec<(String, IrType)>, // name and type of each local
    pub blocks: Vec<BasicBlock>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IrProgram {
    pub module_name: String,
    pub capabilities: Vec<String>,
    pub functions: Vec<IrFunction>,
}

impl fmt::Display for IrProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "module @{} {{", self.module_name)?;
        for cap in &self.capabilities {
            writeln!(f, "  requires {};", cap)?;
        }
        for func in &self.functions {
            writeln!(
                f,
                "  fn @{}({}) -> {} {{",
                func.name,
                func.params
                    .iter()
                    .map(|(n, t)| format!("{}: {}", n, t))
                    .collect::<Vec<_>>()
                    .join(", "),
                func.return_type
            )?;
            for (idx, (n, t)) in func.locals.iter().enumerate() {
                writeln!(f, "    .local loc_{} ({}): {}", idx, n, t)?;
            }
            for bb in &func.blocks {
                writeln!(f, "  bb_{} ({}):", bb.id, bb.label)?;
                for inst in &bb.instructions {
                    match inst {
                        IrInst::Assign { dest, src } => writeln!(f, "    {} = {}", dest, src)?,
                        IrInst::Binary { dest, op, lhs, rhs } => {
                            writeln!(f, "    {} = {:?} {}, {}", dest, op, lhs, rhs)?
                        }
                        IrInst::Unary { dest, op, operand } => {
                            writeln!(f, "    {} = {:?} {}", dest, op, operand)?
                        }
                        IrInst::Call { dest, callee, args } => {
                            let args_str = args
                                .iter()
                                .map(|a| a.to_string())
                                .collect::<Vec<_>>()
                                .join(", ");
                            if let Some(d) = dest {
                                writeln!(f, "    {} = call @{}({})", d, callee, args_str)?;
                            } else {
                                writeln!(f, "    call @{}({})", callee, args_str)?;
                            }
                        }
                    }
                }
                match &bb.terminator {
                    IrTerminator::Return(Some(op)) => writeln!(f, "    ret {}", op)?,
                    IrTerminator::Return(None) => writeln!(f, "    ret void")?,
                    IrTerminator::Jump(target) => writeln!(f, "    jmp bb_{}", target)?,
                    IrTerminator::Branch {
                        cond,
                        then_block,
                        else_block,
                    } => writeln!(f, "    br {}, bb_{}, bb_{}", cond, then_block, else_block)?,
                }
            }
            writeln!(f, "  }}")?;
        }
        writeln!(f, "}}")?;
        Ok(())
    }
}

pub struct IrLowerer {
    next_temp: usize,
    next_block_id: usize,
    current_block_id: usize,
    current_terminated: bool,
    locals: Vec<(String, IrType)>,
    local_indices: HashMap<String, usize>,
    blocks: Vec<BasicBlock>,
    current_insts: Vec<IrInst>,
}

impl IrLowerer {
    pub fn new() -> Self {
        Self {
            next_temp: 0,
            next_block_id: 0,
            current_block_id: 0,
            current_terminated: false,
            locals: Vec::new(),
            local_indices: HashMap::new(),
            blocks: Vec::new(),
            current_insts: Vec::new(),
        }
    }
}

impl Default for IrLowerer {
    fn default() -> Self {
        Self::new()
    }
}

impl IrLowerer {
    fn new_temp(&mut self) -> IrOperand {
        let t = self.next_temp;
        self.next_temp += 1;
        IrOperand::Temp(t)
    }

    fn new_block_id(&mut self) -> usize {
        let b = self.next_block_id;
        self.next_block_id += 1;
        b
    }

    pub fn lower_program(program: &Program) -> Result<IrProgram, Diagnostic> {
        let mut ir_functions = Vec::new();
        let capabilities = program
            .capabilities
            .iter()
            .map(|c| c.name.clone())
            .collect();

        for f in &program.functions {
            let mut lowerer = IrLowerer::new();
            let ir_fn = lowerer.lower_function(f)?;
            ir_functions.push(ir_fn);
        }

        let ir_prog = IrProgram {
            module_name: program.module_name.clone(),
            capabilities,
            functions: ir_functions,
        };

        Self::verify_ir(&ir_prog)?;
        Ok(ir_prog)
    }

    fn lower_function(&mut self, f: &FunctionDecl) -> Result<IrFunction, Diagnostic> {
        self.next_temp = 0;
        self.next_block_id = 0;
        self.locals.clear();
        self.local_indices.clear();
        self.blocks.clear();
        self.current_insts.clear();

        let mut params = Vec::new();
        for p in &f.params {
            let p_ty = IrType::from(p.ty);
            let idx = self.locals.len();
            self.locals.push((p.name.clone(), p_ty));
            self.local_indices.insert(p.name.clone(), idx);
            params.push((p.name.clone(), p_ty));
        }

        let entry_id = self.new_block_id();
        self.start_block(entry_id);
        let ret_ty = IrType::from(f.return_type);

        self.lower_block(&f.body)?;

        // Ensure entry block or current block has a terminator
        if !self.current_terminated {
            let default_term = if ret_ty == IrType::Void {
                IrTerminator::Return(None)
            } else {
                IrTerminator::Return(Some(IrOperand::ConstI32(0)))
            };
            self.finish_block("exit", default_term);
        }

        Ok(IrFunction {
            name: f.name.clone(),
            params,
            return_type: ret_ty,
            locals: self.locals.clone(),
            blocks: self.blocks.clone(),
        })
    }

    fn start_block(&mut self, id: usize) {
        self.current_block_id = id;
        self.current_terminated = false;
    }

    fn finish_block(&mut self, label: &str, terminator: IrTerminator) {
        let instructions = std::mem::take(&mut self.current_insts);
        self.blocks.push(BasicBlock {
            id: self.current_block_id,
            label: label.to_string(),
            instructions,
            terminator,
        });
        self.current_terminated = true;
    }

    fn lower_block(&mut self, block: &Block) -> Result<(), Diagnostic> {
        for stmt in &block.statements {
            self.lower_statement(stmt)?;
        }
        Ok(())
    }

    fn lower_statement(&mut self, stmt: &Statement) -> Result<(), Diagnostic> {
        if self.current_terminated {
            return Ok(());
        }

        match stmt {
            Statement::Let {
                name,
                ty,
                init,
                span: _,
                is_mut: _,
            } => {
                let init_op = self.lower_expr(init)?;
                let ir_ty = ty.map(IrType::from).unwrap_or(IrType::I32);
                let idx = self.locals.len();
                self.locals.push((name.clone(), ir_ty));
                self.local_indices.insert(name.clone(), idx);

                self.current_insts.push(IrInst::Assign {
                    dest: IrOperand::Local(idx),
                    src: init_op,
                });
                Ok(())
            }
            Statement::Assign {
                target,
                value,
                span: _,
            } => {
                let val_op = self.lower_expr(value)?;
                let idx = *self.local_indices.get(target).unwrap();
                self.current_insts.push(IrInst::Assign {
                    dest: IrOperand::Local(idx),
                    src: val_op,
                });
                Ok(())
            }
            Statement::If {
                cond,
                then_block,
                else_block,
                span: _,
            } => {
                let cond_op = self.lower_expr(cond)?;
                let then_id = self.new_block_id();
                let else_id = self.new_block_id();
                let merge_id = self.new_block_id();

                self.finish_block(
                    "if.cond",
                    IrTerminator::Branch {
                        cond: cond_op,
                        then_block: then_id,
                        else_block: else_id,
                    },
                );

                // Then block
                self.start_block(then_id);
                self.lower_block(then_block)?;
                if !self.current_terminated {
                    self.finish_block("if.then", IrTerminator::Jump(merge_id));
                }

                // Else block
                self.start_block(else_id);
                if let Some(eb) = else_block {
                    self.lower_block(eb)?;
                }
                if !self.current_terminated {
                    self.finish_block("if.else", IrTerminator::Jump(merge_id));
                }

                // Merge block continues as active block
                self.start_block(merge_id);
                Ok(())
            }
            Statement::While {
                cond,
                body,
                span: _,
            } => {
                let cond_id = self.new_block_id();
                let body_id = self.new_block_id();
                let exit_id = self.new_block_id();

                self.finish_block("while.pre", IrTerminator::Jump(cond_id));

                // Condition block
                self.start_block(cond_id);
                let cond_op = self.lower_expr(cond)?;
                self.finish_block(
                    "while.cond",
                    IrTerminator::Branch {
                        cond: cond_op,
                        then_block: body_id,
                        else_block: exit_id,
                    },
                );

                // Body block
                self.start_block(body_id);
                self.lower_block(body)?;
                if !self.current_terminated {
                    self.finish_block("while.body", IrTerminator::Jump(cond_id));
                }

                // Exit block continues as active block
                self.start_block(exit_id);
                Ok(())
            }
            Statement::Return { value, span: _ } => {
                let ret_op = if let Some(v) = value {
                    Some(self.lower_expr(v)?)
                } else {
                    None
                };
                self.finish_block("ret.block", IrTerminator::Return(ret_op));
                Ok(())
            }
            Statement::Expr(e) => {
                self.lower_expr(e)?;
                Ok(())
            }
        }
    }

    fn lower_expr(&mut self, expr: &Expr) -> Result<IrOperand, Diagnostic> {
        match expr {
            Expr::Integer(v, _) => Ok(IrOperand::ConstI32(*v as i32)),
            Expr::Boolean(b, _) => Ok(IrOperand::ConstBool(*b)),
            Expr::Variable(name, _) => {
                let idx = *self.local_indices.get(name).unwrap();
                Ok(IrOperand::Local(idx))
            }
            Expr::Binary {
                op,
                lhs,
                rhs,
                span: _,
            } => {
                let l_op = self.lower_expr(lhs)?;
                let r_op = self.lower_expr(rhs)?;
                let dest = self.new_temp();
                let ir_op = match op {
                    BinaryOp::Add => IrBinaryOp::Add,
                    BinaryOp::Sub => IrBinaryOp::Sub,
                    BinaryOp::Mul => IrBinaryOp::Mul,
                    BinaryOp::Div => IrBinaryOp::Div,
                    BinaryOp::Rem => IrBinaryOp::Rem,
                    BinaryOp::Eq => IrBinaryOp::Eq,
                    BinaryOp::Neq => IrBinaryOp::Neq,
                    BinaryOp::Lt => IrBinaryOp::Lt,
                    BinaryOp::Lte => IrBinaryOp::Lte,
                    BinaryOp::Gt => IrBinaryOp::Gt,
                    BinaryOp::Gte => IrBinaryOp::Gte,
                    BinaryOp::And => IrBinaryOp::And,
                    BinaryOp::Or => IrBinaryOp::Or,
                };
                self.current_insts.push(IrInst::Binary {
                    dest: dest.clone(),
                    op: ir_op,
                    lhs: l_op,
                    rhs: r_op,
                });
                Ok(dest)
            }
            Expr::Unary { op, expr, span: _ } => {
                let inner = self.lower_expr(expr)?;
                let dest = self.new_temp();
                let ir_op = match op {
                    UnaryOp::Neg => IrUnaryOp::Neg,
                    UnaryOp::Not => IrUnaryOp::Not,
                };
                self.current_insts.push(IrInst::Unary {
                    dest: dest.clone(),
                    op: ir_op,
                    operand: inner,
                });
                Ok(dest)
            }
            Expr::Call {
                callee,
                args,
                span: _,
            } => {
                let mut ir_args = Vec::new();
                for a in args {
                    ir_args.push(self.lower_expr(a)?);
                }
                let dest = if callee == "print_i32" || callee == "print_bool" {
                    None
                } else {
                    Some(self.new_temp())
                };
                self.current_insts.push(IrInst::Call {
                    dest: dest.clone(),
                    callee: callee.clone(),
                    args: ir_args,
                });
                Ok(dest.unwrap_or(IrOperand::ConstI32(0)))
            }
            Expr::Block(b) => {
                self.lower_block(b)?;
                Ok(IrOperand::ConstI32(0))
            }
        }
    }

    pub fn verify_ir(prog: &IrProgram) -> Result<(), Diagnostic> {
        for f in &prog.functions {
            let block_ids: std::collections::HashSet<usize> =
                f.blocks.iter().map(|b| b.id).collect();
            for b in &f.blocks {
                match &b.terminator {
                    IrTerminator::Jump(target) => {
                        if !block_ids.contains(target) {
                            return Err(Diagnostic::error(
                                format!(
                                    "IR Verification failure: Function '{}' block {} jumps to non-existent block {}",
                                    f.name, b.id, target
                                ),
                                Span::point(1, 1),
                            ));
                        }
                    }
                    IrTerminator::Branch {
                        then_block,
                        else_block,
                        ..
                    } => {
                        if !block_ids.contains(then_block) || !block_ids.contains(else_block) {
                            return Err(Diagnostic::error(
                                format!(
                                    "IR Verification failure: Function '{}' block {} branches to non-existent blocks ({}, {})",
                                    f.name, b.id, then_block, else_block
                                ),
                                Span::point(1, 1),
                            ));
                        }
                    }
                    IrTerminator::Return(_) => {}
                }
            }
        }
        Ok(())
    }
}
