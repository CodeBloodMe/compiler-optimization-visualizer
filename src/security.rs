use std::collections::HashMap;
use crate::ast::*;
use crate::source::Span;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintState {
    Clean,
    Tainted {
        source_name: String,
        source_span: Span,
    },
    Sanitized {
        source_name: String,
        sanitizer: String,
        span: Span,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingKind {
    Vulnerability, // Tainted data reached sink without sanitization
    Warning,       // Conservative warning
    SafeFlow,      // Tainted data properly sanitized before reaching sink
}

#[derive(Debug, Clone)]
pub struct TaintFinding {
    pub kind: FindingKind,
    pub source: String,
    pub sink: String,
    pub span: Span,
    pub description: String,
    pub flow_path: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TaintReport {
    pub findings: Vec<TaintFinding>,
    pub analyzed_functions: usize,
}

impl TaintReport {
    pub fn has_vulnerabilities(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.kind == FindingKind::Vulnerability)
    }

    pub fn vulnerability_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.kind == FindingKind::Vulnerability)
            .count()
    }

    pub fn safe_flow_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.kind == FindingKind::SafeFlow)
            .count()
    }
}

pub struct TaintAnalyzer {
    variable_taint: HashMap<String, TaintState>,
    flow_steps: HashMap<String, Vec<String>>,
    findings: Vec<TaintFinding>,
}

impl TaintAnalyzer {
    pub fn new() -> Self {
        Self {
            variable_taint: HashMap::new(),
            flow_steps: HashMap::new(),
            findings: Vec::new(),
        }
    }

    pub fn analyze_program(program: &Program) -> TaintReport {
        let mut analyzer = TaintAnalyzer::new();
        let mut analyzed_functions = 0;

        for f in &program.functions {
            analyzer.analyze_function(f);
            analyzed_functions += 1;
        }

        TaintReport {
            findings: analyzer.findings,
            analyzed_functions,
        }
    }

    fn analyze_function(&mut self, f: &FunctionDecl) {
        self.variable_taint.clear();
        self.flow_steps.clear();

        for p in &f.params {
            self.variable_taint
                .insert(p.name.clone(), TaintState::Clean);
            self.flow_steps
                .insert(p.name.clone(), vec![format!("param '{}'", p.name)]);
        }

        self.analyze_block(&f.body);
    }

    fn analyze_block(&mut self, block: &Block) {
        for stmt in &block.statements {
            self.analyze_statement(stmt);
        }
    }

    fn analyze_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Let {
                name,
                init,
                span: _,
                ..
            } => {
                let (init_taint, step) = self.eval_expr_taint(init);
                let mut path = match &init_taint {
                    TaintState::Tainted { source_name, .. } => {
                        vec![format!("source: {}", source_name), format!("assigned to '{}'", name)]
                    }
                    TaintState::Sanitized { sanitizer, .. } => {
                        vec![format!("sanitized via '{}'", sanitizer), format!("assigned to '{}'", name)]
                    }
                    TaintState::Clean => vec![format!("clean literal assigned to '{}'", name)],
                };
                if let Some(s) = step {
                    path.push(s);
                }
                self.variable_taint.insert(name.clone(), init_taint);
                self.flow_steps.insert(name.clone(), path);
            }
            Statement::Assign {
                target,
                value,
                span: _,
            } => {
                let (val_taint, step) = self.eval_expr_taint(value);
                let mut path = match &val_taint {
                    TaintState::Tainted { source_name, .. } => {
                        vec![format!("source: {}", source_name), format!("reassigned to '{}'", target)]
                    }
                    TaintState::Sanitized { sanitizer, .. } => {
                        vec![format!("sanitized via '{}'", sanitizer), format!("reassigned to '{}'", target)]
                    }
                    TaintState::Clean => vec![format!("clean value reassigned to '{}'", target)],
                };
                if let Some(s) = step {
                    path.push(s);
                }
                self.variable_taint.insert(target.clone(), val_taint);
                self.flow_steps.insert(target.clone(), path);
            }
            Statement::If {
                then_block,
                else_block,
                ..
            } => {
                self.analyze_block(then_block);
                if let Some(eb) = else_block {
                    self.analyze_block(eb);
                }
            }
            Statement::While { body, .. } => {
                self.analyze_block(body);
            }
            Statement::Return { .. } => {}
            Statement::Expr(e) => {
                self.eval_expr_taint(e);
            }
        }
    }

    fn eval_expr_taint(&mut self, expr: &Expr) -> (TaintState, Option<String>) {
        match expr {
            Expr::Integer(_, _) | Expr::Boolean(_, _) => (TaintState::Clean, None),
            Expr::Variable(name, _) => {
                let state = self
                    .variable_taint
                    .get(name)
                    .cloned()
                    .unwrap_or(TaintState::Clean);
                (state, Some(format!("var '{}'", name)))
            }
            Expr::Binary { lhs, rhs, op, .. } => {
                let (l_taint, _) = self.eval_expr_taint(lhs);
                let (r_taint, _) = self.eval_expr_taint(rhs);

                match (&l_taint, &r_taint) {
                    (TaintState::Tainted { .. }, _) => (l_taint, Some(format!("binary op {:?}", op))),
                    (_, TaintState::Tainted { .. }) => (r_taint, Some(format!("binary op {:?}", op))),
                    (TaintState::Sanitized { .. }, _) => (l_taint, Some(format!("binary op {:?}", op))),
                    (_, TaintState::Sanitized { .. }) => (r_taint, Some(format!("binary op {:?}", op))),
                    _ => (TaintState::Clean, None),
                }
            }
            Expr::Unary { expr, op, .. } => {
                let (inner_taint, _) = self.eval_expr_taint(expr);
                (inner_taint, Some(format!("unary op {:?}", op)))
            }
            Expr::Call { callee, args, span } => {
                // Check if this is a taint source
                if callee == "read_i32" {
                    return (
                        TaintState::Tainted {
                            source_name: "read_i32()".to_string(),
                            source_span: *span,
                        },
                        Some("called read_i32() (untrusted input source)".to_string()),
                    );
                }

                // Check if this is a sanitizer
                if callee == "sanitize_i32" && !args.is_empty() {
                    let (arg_taint, _) = self.eval_expr_taint(&args[0]);
                    return match arg_taint {
                        TaintState::Tainted { source_name, .. } => (
                            TaintState::Sanitized {
                                source_name,
                                sanitizer: "sanitize_i32".to_string(),
                                span: *span,
                            },
                            Some("sanitized via sanitize_i32()".to_string()),
                        ),
                        other => (other, Some("called sanitize_i32()".to_string())),
                    };
                }

                // Check if this is a sensitive sink
                if callee == "print_i32" || callee == "print_bool" {
                    if let Some(arg) = args.first() {
                        let (arg_taint, _) = self.eval_expr_taint(arg);
                        match arg_taint {
                            TaintState::Tainted {
                                source_name,
                                source_span: _,
                            } => {
                                let path = vec![
                                    format!("Source: {}", source_name),
                                    format!("Propagated into call argument"),
                                    format!("Sink: {}(...)", callee),
                                ];
                                self.findings.push(TaintFinding {
                                    kind: FindingKind::Vulnerability,
                                    source: source_name,
                                    sink: callee.clone(),
                                    span: *span,
                                    description: format!(
                                        "Security vulnerability: Untrusted value from source flows directly to sensitive sink '{}' without sanitization",
                                        callee
                                    ),
                                    flow_path: path,
                                });
                            }
                            TaintState::Sanitized {
                                source_name,
                                sanitizer,
                                ..
                            } => {
                                let path = vec![
                                    format!("Source: {}", source_name),
                                    format!("Sanitizer: {}", sanitizer),
                                    format!("Sink: {}(...)", callee),
                                ];
                                self.findings.push(TaintFinding {
                                    kind: FindingKind::SafeFlow,
                                    source: source_name,
                                    sink: callee.clone(),
                                    span: *span,
                                    description: format!(
                                        "Safe flow: Untrusted value sanitized by '{}' before reaching sink '{}'",
                                        sanitizer, callee
                                    ),
                                    flow_path: path,
                                });
                            }
                            TaintState::Clean => {}
                        }
                    }
                }

                (TaintState::Clean, Some(format!("called {}", callee)))
            }
            Expr::Block(b) => {
                self.analyze_block(b);
                (TaintState::Clean, None)
            }
        }
    }
}
