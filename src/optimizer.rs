use crate::ast::*;

pub struct Optimizer {
    pub folding_count: usize,
    pub simplification_count: usize,
    pub dce_count: usize,
}

impl Optimizer {
    pub fn new() -> Self {
        Self {
            folding_count: 0,
            simplification_count: 0,
            dce_count: 0,
        }
    }

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

    fn optimize_expr(&mut self, expr: &mut Expr) {
        match expr {
            Expr::Integer(_, _) | Expr::Boolean(_, _) | Expr::Variable(_, _) => {}
            Expr::Unary { op, expr: inner, span } => {
                self.optimize_expr(inner);
                match (op, &**inner) {
                    (UnaryOp::Neg, Expr::Integer(val, _)) => {
                        *expr = Expr::Integer(-val, *span);
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
                    let folded = match op {
                        BinaryOp::Add => Some(Expr::Integer(l.wrapping_add(*r), *span)),
                        BinaryOp::Sub => Some(Expr::Integer(l.wrapping_sub(*r), *span)),
                        BinaryOp::Mul => Some(Expr::Integer(l.wrapping_mul(*r), *span)),
                        BinaryOp::Div if *r != 0 => Some(Expr::Integer(l.wrapping_div(*r), *span)),
                        BinaryOp::Rem if *r != 0 => Some(Expr::Integer(l.wrapping_rem(*r), *span)),
                        BinaryOp::Eq => Some(Expr::Boolean(l == r, *span)),
                        BinaryOp::Neq => Some(Expr::Boolean(l != r, *span)),
                        BinaryOp::Lt => Some(Expr::Boolean(l < r, *span)),
                        BinaryOp::Lte => Some(Expr::Boolean(l <= r, *span)),
                        BinaryOp::Gt => Some(Expr::Boolean(l > r, *span)),
                        BinaryOp::Gte => Some(Expr::Boolean(l >= r, *span)),
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
