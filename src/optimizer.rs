use crate::ast::*;
use crate::ir::*;
use std::collections::{HashSet, VecDeque};

pub type Optimizer = AstOptimizer;

/// AST-level semantic-preserving optimization pass.
/// Performs early constant folding, algebraic simplification, and syntactic dead code elimination.
pub struct AstOptimizer {
    pub folding_count: usize,
    pub simplification_count: usize,
    pub dce_count: usize,
}

impl AstOptimizer {
    pub fn new() -> Self {
        Self {
            folding_count: 0,
            simplification_count: 0,
            dce_count: 0,
        }
    }
}

impl Default for AstOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl AstOptimizer {
    pub fn optimize_program(&mut self, program: &Program) -> Program {
        let mut optimized = program.clone();
        for func in &mut optimized.functions {
            self.optimize_function(func);
        }
        optimized
    }

    fn optimize_function(&mut self, func: &mut FunctionDecl) {
        self.optimize_block(&mut func.body);
    }

    fn optimize_block(&mut self, block: &mut Block) {
        let mut new_stmts = Vec::new();
        let mut has_returned = false;

        for stmt in &mut block.statements {
            if has_returned {
                // Dead code elimination: prune unreachable statements after return
                self.dce_count += 1;
                continue;
            }

            match stmt {
                Statement::Let { init, .. } => {
                    self.optimize_expr(init);
                    new_stmts.push(stmt.clone());
                }
                Statement::Assign { value, .. } => {
                    self.optimize_expr(value);
                    new_stmts.push(stmt.clone());
                }
                Statement::If {
                    cond,
                    then_block,
                    else_block,
                    ..
                } => {
                    self.optimize_expr(cond);
                    self.optimize_block(then_block);
                    if let Some(eb) = else_block {
                        self.optimize_block(eb);
                    }

                    // Check if condition folded into constant boolean
                    match cond {
                        Expr::Boolean(true, _) => {
                            self.dce_count += 1;
                            new_stmts.extend(then_block.statements.clone());
                        }
                        Expr::Boolean(false, _) => {
                            self.dce_count += 1;
                            if let Some(eb) = else_block {
                                new_stmts.extend(eb.statements.clone());
                            }
                        }
                        _ => {
                            new_stmts.push(stmt.clone());
                        }
                    }
                }
                Statement::While { cond, body, .. } => {
                    self.optimize_expr(cond);
                    self.optimize_block(body);
                    new_stmts.push(stmt.clone());
                }
                Statement::Return { value, .. } => {
                    if let Some(expr) = value {
                        self.optimize_expr(expr);
                    }
                    new_stmts.push(stmt.clone());
                    has_returned = true;
                }
                Statement::Expr(expr) => {
                    self.optimize_expr(expr);
                    new_stmts.push(stmt.clone());
                }
            }
        }

        block.statements = new_stmts;
    }

    fn has_side_effects(expr: &Expr) -> bool {
        match expr {
            Expr::Call { .. } => true,
            Expr::Binary { lhs, rhs, .. } => {
                Self::has_side_effects(lhs) || Self::has_side_effects(rhs)
            }
            Expr::Unary { expr, .. } => Self::has_side_effects(expr),
            Expr::Block(b) => b.statements.iter().any(|s| match s {
                Statement::Expr(e) => Self::has_side_effects(e),
                Statement::Let { init, .. } => Self::has_side_effects(init),
                Statement::Assign { value, .. } => Self::has_side_effects(value),
                _ => true,
            }),
            _ => false,
        }
    }

    fn optimize_expr(&mut self, expr: &mut Expr) {
        match expr {
            Expr::Integer(_, _) | Expr::Boolean(_, _) | Expr::Variable(_, _) => {}
            Expr::Unary {
                op,
                expr: inner,
                span,
            } => {
                self.optimize_expr(inner);
                match (op, &**inner) {
                    (UnaryOp::Neg, Expr::Integer(val, _)) => {
                        let v32 = *val as i32;
                        *expr = Expr::Integer(v32.wrapping_neg() as i64, *span);
                        self.folding_count += 1;
                    }
                    (UnaryOp::Not, Expr::Boolean(b, _)) => {
                        *expr = Expr::Boolean(!b, *span);
                        self.folding_count += 1;
                    }
                    _ => {}
                }
            }
            Expr::Binary { op, lhs, rhs, span } => {
                self.optimize_expr(lhs);
                self.optimize_expr(rhs);

                // 1. Constant folding
                if let (Expr::Integer(l, _), Expr::Integer(r, _)) = (&**lhs, &**rhs) {
                    let l32 = *l as i32;
                    let r32 = *r as i32;
                    let folded = match op {
                        BinaryOp::Add => Some(Expr::Integer(l32.wrapping_add(r32) as i64, *span)),
                        BinaryOp::Sub => Some(Expr::Integer(l32.wrapping_sub(r32) as i64, *span)),
                        BinaryOp::Mul => Some(Expr::Integer(l32.wrapping_mul(r32) as i64, *span)),
                        // WebAssembly i32.div_s traps on division by zero and on i32::MIN / -1.
                        // Do not fold these into constants so runtime trap behavior is preserved.
                        BinaryOp::Div if r32 != 0 && !(l32 == i32::MIN && r32 == -1) => {
                            Some(Expr::Integer(l32.wrapping_div(r32) as i64, *span))
                        }
                        // WebAssembly i32.rem_s traps on division by zero.
                        BinaryOp::Rem if r32 != 0 => {
                            Some(Expr::Integer(l32.wrapping_rem(r32) as i64, *span))
                        }
                        BinaryOp::Eq => Some(Expr::Boolean(l32 == r32, *span)),
                        BinaryOp::Neq => Some(Expr::Boolean(l32 != r32, *span)),
                        BinaryOp::Lt => Some(Expr::Boolean(l32 < r32, *span)),
                        BinaryOp::Lte => Some(Expr::Boolean(l32 <= r32, *span)),
                        BinaryOp::Gt => Some(Expr::Boolean(l32 > r32, *span)),
                        BinaryOp::Gte => Some(Expr::Boolean(l32 >= r32, *span)),
                        _ => None,
                    };
                    if let Some(f) = folded {
                        *expr = f;
                        self.folding_count += 1;
                        return;
                    }
                }

                if let (Expr::Boolean(l, _), Expr::Boolean(r, _)) = (&**lhs, &**rhs) {
                    let folded = match op {
                        BinaryOp::And => Some(Expr::Boolean(*l && *r, *span)),
                        BinaryOp::Or => Some(Expr::Boolean(*l || *r, *span)),
                        BinaryOp::Eq => Some(Expr::Boolean(l == r, *span)),
                        BinaryOp::Neq => Some(Expr::Boolean(l != r, *span)),
                        _ => None,
                    };
                    if let Some(f) = folded {
                        *expr = f;
                        self.folding_count += 1;
                        return;
                    }
                }

                // 2. Algebraic simplification
                match op {
                    BinaryOp::Add => {
                        if let Expr::Integer(0, _) = &**rhs {
                            *expr = *lhs.clone();
                            self.simplification_count += 1;
                        } else if let Expr::Integer(0, _) = &**lhs {
                            *expr = *rhs.clone();
                            self.simplification_count += 1;
                        }
                    }
                    BinaryOp::Sub => {
                        if let Expr::Integer(0, _) = &**rhs {
                            *expr = *lhs.clone();
                            self.simplification_count += 1;
                        }
                    }
                    BinaryOp::Mul => {
                        if let Expr::Integer(1, _) = &**rhs {
                            *expr = *lhs.clone();
                            self.simplification_count += 1;
                        } else if let Expr::Integer(1, _) = &**lhs {
                            *expr = *rhs.clone();
                            self.simplification_count += 1;
                        } else if (matches!(&**rhs, Expr::Integer(0, _))
                            && !Self::has_side_effects(lhs))
                            || (matches!(&**lhs, Expr::Integer(0, _))
                                && !Self::has_side_effects(rhs))
                        {
                            *expr = Expr::Integer(0, *span);
                            self.simplification_count += 1;
                        }
                    }
                    _ => {}
                }
            }
            Expr::Call { args, .. } => {
                for a in args {
                    self.optimize_expr(a);
                }
            }
            Expr::Block(block) => {
                self.optimize_block(block);
            }
        }
    }
}

/// Intermediate Representation Optimizer.
/// Performs constant folding, algebraic simplification, and control-flow dead-block elimination
/// directly on the typed basic blocks and instructions of IrProgram.
pub struct IrOptimizer {
    pub folding_count: usize,
    pub simplification_count: usize,
    pub dce_count: usize,
}

impl IrOptimizer {
    pub fn new() -> Self {
        Self {
            folding_count: 0,
            simplification_count: 0,
            dce_count: 0,
        }
    }
}

impl Default for IrOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl IrOptimizer {
    pub fn optimize_program(&mut self, prog: &IrProgram) -> IrProgram {
        let mut optimized = prog.clone();
        for func in &mut optimized.functions {
            self.optimize_function(func);
        }
        optimized
    }

    fn optimize_function(&mut self, func: &mut IrFunction) {
        // Step 1: Optimize instructions within each basic block
        for bb in &mut func.blocks {
            self.optimize_block(bb);
        }

        // Step 2: Simplify control flow terminators (branches with constant conditions)
        for bb in &mut func.blocks {
            if let IrTerminator::Branch {
                cond,
                then_block,
                else_block,
            } = &bb.terminator
            {
                match cond {
                    IrOperand::ConstBool(true) => {
                        bb.terminator = IrTerminator::Jump(*then_block);
                        self.dce_count += 1;
                    }
                    IrOperand::ConstBool(false) => {
                        bb.terminator = IrTerminator::Jump(*else_block);
                        self.dce_count += 1;
                    }
                    _ => {}
                }
            }
        }

        // Step 3: Dead block elimination (prune blocks unreachable from entry block)
        if !func.blocks.is_empty() {
            let entry_id = func.blocks[0].id;
            let mut reachable = HashSet::new();
            let mut queue = VecDeque::new();
            queue.push_back(entry_id);
            reachable.insert(entry_id);

            let block_map: std::collections::HashMap<usize, &BasicBlock> =
                func.blocks.iter().map(|b| (b.id, b)).collect();

            while let Some(curr_id) = queue.pop_front() {
                if let Some(bb) = block_map.get(&curr_id) {
                    match &bb.terminator {
                        IrTerminator::Jump(target) => {
                            if reachable.insert(*target) {
                                queue.push_back(*target);
                            }
                        }
                        IrTerminator::Branch {
                            then_block,
                            else_block,
                            ..
                        } => {
                            if reachable.insert(*then_block) {
                                queue.push_back(*then_block);
                            }
                            if reachable.insert(*else_block) {
                                queue.push_back(*else_block);
                            }
                        }
                        IrTerminator::Return(_) => {}
                    }
                }
            }

            let initial_len = func.blocks.len();
            func.blocks.retain(|b| reachable.contains(&b.id));
            let removed = initial_len - func.blocks.len();
            self.dce_count += removed;
        }
    }

    fn optimize_block(&mut self, bb: &mut BasicBlock) {
        let mut new_insts = Vec::new();

        for inst in &bb.instructions {
            match inst {
                IrInst::Binary { dest, op, lhs, rhs } => {
                    // Constant folding
                    if let (IrOperand::ConstI32(l), IrOperand::ConstI32(r)) = (lhs, rhs) {
                        let folded = match op {
                            IrBinaryOp::Add => Some(IrOperand::ConstI32(l.wrapping_add(*r))),
                            IrBinaryOp::Sub => Some(IrOperand::ConstI32(l.wrapping_sub(*r))),
                            IrBinaryOp::Mul => Some(IrOperand::ConstI32(l.wrapping_mul(*r))),
                            // Preserve WebAssembly trap semantics for div by zero and i32::MIN / -1
                            IrBinaryOp::Div if *r != 0 && !(*l == i32::MIN && *r == -1) => {
                                Some(IrOperand::ConstI32(l.wrapping_div(*r)))
                            }
                            IrBinaryOp::Rem if *r != 0 => {
                                Some(IrOperand::ConstI32(l.wrapping_rem(*r)))
                            }
                            IrBinaryOp::Eq => Some(IrOperand::ConstBool(l == r)),
                            IrBinaryOp::Neq => Some(IrOperand::ConstBool(l != r)),
                            IrBinaryOp::Lt => Some(IrOperand::ConstBool(l < r)),
                            IrBinaryOp::Lte => Some(IrOperand::ConstBool(l <= r)),
                            IrBinaryOp::Gt => Some(IrOperand::ConstBool(l > r)),
                            IrBinaryOp::Gte => Some(IrOperand::ConstBool(l >= r)),
                            _ => None,
                        };

                        if let Some(val) = folded {
                            self.folding_count += 1;
                            new_insts.push(IrInst::Assign {
                                dest: dest.clone(),
                                src: val,
                            });
                            continue;
                        }
                    }

                    if let (IrOperand::ConstBool(l), IrOperand::ConstBool(r)) = (lhs, rhs) {
                        let folded = match op {
                            IrBinaryOp::And => Some(IrOperand::ConstBool(*l && *r)),
                            IrBinaryOp::Or => Some(IrOperand::ConstBool(*l || *r)),
                            IrBinaryOp::Eq => Some(IrOperand::ConstBool(l == r)),
                            IrBinaryOp::Neq => Some(IrOperand::ConstBool(l != r)),
                            _ => None,
                        };

                        if let Some(val) = folded {
                            self.folding_count += 1;
                            new_insts.push(IrInst::Assign {
                                dest: dest.clone(),
                                src: val,
                            });
                            continue;
                        }
                    }

                    // Algebraic simplification
                    match op {
                        IrBinaryOp::Add => {
                            if let IrOperand::ConstI32(0) = rhs {
                                self.simplification_count += 1;
                                new_insts.push(IrInst::Assign {
                                    dest: dest.clone(),
                                    src: lhs.clone(),
                                });
                                continue;
                            } else if let IrOperand::ConstI32(0) = lhs {
                                self.simplification_count += 1;
                                new_insts.push(IrInst::Assign {
                                    dest: dest.clone(),
                                    src: rhs.clone(),
                                });
                                continue;
                            }
                        }
                        IrBinaryOp::Sub => {
                            if let IrOperand::ConstI32(0) = rhs {
                                self.simplification_count += 1;
                                new_insts.push(IrInst::Assign {
                                    dest: dest.clone(),
                                    src: lhs.clone(),
                                });
                                continue;
                            }
                        }
                        IrBinaryOp::Mul => {
                            if let IrOperand::ConstI32(1) = rhs {
                                self.simplification_count += 1;
                                new_insts.push(IrInst::Assign {
                                    dest: dest.clone(),
                                    src: lhs.clone(),
                                });
                                continue;
                            } else if let IrOperand::ConstI32(1) = lhs {
                                self.simplification_count += 1;
                                new_insts.push(IrInst::Assign {
                                    dest: dest.clone(),
                                    src: rhs.clone(),
                                });
                                continue;
                            } else if let IrOperand::ConstI32(0) = rhs {
                                self.simplification_count += 1;
                                new_insts.push(IrInst::Assign {
                                    dest: dest.clone(),
                                    src: IrOperand::ConstI32(0),
                                });
                                continue;
                            } else if let IrOperand::ConstI32(0) = lhs {
                                self.simplification_count += 1;
                                new_insts.push(IrInst::Assign {
                                    dest: dest.clone(),
                                    src: IrOperand::ConstI32(0),
                                });
                                continue;
                            }
                        }
                        _ => {}
                    }

                    new_insts.push(inst.clone());
                }
                IrInst::Unary { dest, op, operand } => match (op, operand) {
                    (IrUnaryOp::Neg, IrOperand::ConstI32(v)) => {
                        self.folding_count += 1;
                        new_insts.push(IrInst::Assign {
                            dest: dest.clone(),
                            src: IrOperand::ConstI32(v.wrapping_neg()),
                        });
                    }
                    (IrUnaryOp::Not, IrOperand::ConstBool(b)) => {
                        self.folding_count += 1;
                        new_insts.push(IrInst::Assign {
                            dest: dest.clone(),
                            src: IrOperand::ConstBool(!b),
                        });
                    }
                    _ => {
                        new_insts.push(inst.clone());
                    }
                },
                _ => {
                    new_insts.push(inst.clone());
                }
            }
        }

        bb.instructions = new_insts;
    }
}
