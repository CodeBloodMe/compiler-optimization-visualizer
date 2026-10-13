use crate::ast::*;
use crate::source::Span;
use std::collections::{HashMap, HashSet};

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

/// Scoped variable taint tracking environment with multi-tier lexical scope support
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintEnv {
    scopes: Vec<HashMap<String, TaintState>>,
    flow_steps: Vec<HashMap<String, Vec<String>>>,
}

impl TaintEnv {
    pub fn new() -> Self {
        Self {
            scopes: vec![HashMap::new()],
            flow_steps: vec![HashMap::new()],
        }
    }
}

impl Default for TaintEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintEnv {
    pub fn enter_scope(&mut self) {
        self.scopes.push(HashMap::new());
        self.flow_steps.push(HashMap::new());
    }

    pub fn exit_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
            self.flow_steps.pop();
        }
    }

    pub fn insert(&mut self, name: String, state: TaintState, steps: Vec<String>) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.clone(), state);
        }
        if let Some(step_map) = self.flow_steps.last_mut() {
            step_map.insert(name, steps);
        }
    }

    pub fn assign(&mut self, name: &str, state: TaintState, steps: Vec<String>) {
        // Find existing variable from innermost to outermost scope
        for (scope, step_map) in self
            .scopes
            .iter_mut()
            .rev()
            .zip(self.flow_steps.iter_mut().rev())
        {
            if scope.contains_key(name) {
                scope.insert(name.to_string(), state);
                step_map.insert(name.to_string(), steps);
                return;
            }
        }
        // Fallback: insert in current scope
        self.insert(name.to_string(), state, steps);
    }

    pub fn get(&self, name: &str) -> Option<&TaintState> {
        for scope in self.scopes.iter().rev() {
            if let Some(st) = scope.get(name) {
                return Some(st);
            }
        }
        None
    }

    pub fn get_steps(&self, name: &str) -> Option<&Vec<String>> {
        for step_map in self.flow_steps.iter().rev() {
            if let Some(st) = step_map.get(name) {
                return Some(st);
            }
        }
        None
    }

    pub fn flattened(&self) -> HashMap<String, (TaintState, Vec<String>)> {
        let mut map = HashMap::new();
        for (scope, step_map) in self.scopes.iter().zip(self.flow_steps.iter()) {
            for (k, v) in scope {
                let steps = step_map.get(k).cloned().unwrap_or_default();
                map.insert(k.clone(), (v.clone(), steps));
            }
        }
        map
    }

    /// Sound branch merge operation: joins two branch environments into base.
    /// If either branch taints variable `x`, `x` is marked as tainted in the joined state.
    pub fn merge(mut base: TaintEnv, branch_a: &TaintEnv, branch_b: &TaintEnv) -> TaintEnv {
        let a_map = branch_a.flattened();
        let b_map = branch_b.flattened();

        for (var_name, base_info) in base.flattened() {
            let (state_a, steps_a) = a_map
                .get(&var_name)
                .map(|(s, st)| (s, st.clone()))
                .unwrap_or((&base_info.0, base_info.1.clone()));
            let (state_b, steps_b) = b_map
                .get(&var_name)
                .map(|(s, st)| (s, st.clone()))
                .unwrap_or((&base_info.0, base_info.1.clone()));

            let (merged_state, merged_steps) = match (state_a, state_b) {
                (
                    TaintState::Tainted {
                        source_name,
                        source_span,
                    },
                    _,
                ) => {
                    let mut st = steps_a;
                    st.push("merged branch: tainted path propagated".to_string());
                    (
                        TaintState::Tainted {
                            source_name: source_name.clone(),
                            source_span: *source_span,
                        },
                        st,
                    )
                }
                (
                    _,
                    TaintState::Tainted {
                        source_name,
                        source_span,
                    },
                ) => {
                    let mut st = steps_b;
                    st.push("merged branch: tainted path propagated".to_string());
                    (
                        TaintState::Tainted {
                            source_name: source_name.clone(),
                            source_span: *source_span,
                        },
                        st,
                    )
                }
                (
                    TaintState::Sanitized {
                        source_name,
                        sanitizer,
                        span,
                    },
                    TaintState::Sanitized { .. },
                ) => (
                    TaintState::Sanitized {
                        source_name: source_name.clone(),
                        sanitizer: sanitizer.clone(),
                        span: *span,
                    },
                    steps_a,
                ),
                (
                    TaintState::Sanitized {
                        source_name,
                        sanitizer,
                        span,
                    },
                    TaintState::Clean,
                ) => (
                    TaintState::Sanitized {
                        source_name: source_name.clone(),
                        sanitizer: sanitizer.clone(),
                        span: *span,
                    },
                    steps_a,
                ),
                (
                    TaintState::Clean,
                    TaintState::Sanitized {
                        source_name,
                        sanitizer,
                        span,
                    },
                ) => (
                    TaintState::Sanitized {
                        source_name: source_name.clone(),
                        sanitizer: sanitizer.clone(),
                        span: *span,
                    },
                    steps_b,
                ),
                (TaintState::Clean, TaintState::Clean) => (
                    TaintState::Clean,
                    vec![format!("clean value in '{}'", var_name)],
                ),
            };

            base.assign(&var_name, merged_state, merged_steps);
        }

        base
    }
}

pub struct TaintAnalyzer {
    pub env: TaintEnv,
    pub findings: Vec<TaintFinding>,
    recorded_keys: HashSet<(String, String, usize, usize)>,
    record_findings: bool,
}

impl TaintAnalyzer {
    pub fn new() -> Self {
        Self {
            env: TaintEnv::new(),
            findings: Vec::new(),
            recorded_keys: HashSet::new(),
            record_findings: true,
        }
    }
}

impl Default for TaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintAnalyzer {
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
        self.env = TaintEnv::new();

        for p in &f.params {
            self.env.insert(
                p.name.clone(),
                TaintState::Clean,
                vec![format!("param '{}'", p.name)],
            );
        }

        self.analyze_block(&f.body);
    }

    fn analyze_block(&mut self, block: &Block) {
        self.env.enter_scope();
        for stmt in &block.statements {
            self.analyze_statement(stmt);
        }
        self.env.exit_scope();
    }

    fn analyze_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Let { name, init, .. } => {
                let (init_taint, step) = self.eval_expr_taint(init);
                let mut path = match &init_taint {
                    TaintState::Tainted { source_name, .. } => {
                        vec![
                            format!("source: {}", source_name),
                            format!("assigned to local '{}'", name),
                        ]
                    }
                    TaintState::Sanitized { sanitizer, .. } => {
                        vec![
                            format!("sanitized via '{}'", sanitizer),
                            format!("assigned to local '{}'", name),
                        ]
                    }
                    TaintState::Clean => vec![format!("clean literal assigned to '{}'", name)],
                };
                if let Some(s) = step {
                    path.push(s);
                }
                self.env.insert(name.clone(), init_taint, path);
            }
            Statement::Assign {
                target,
                value,
                span: _,
            } => {
                let (val_taint, step) = self.eval_expr_taint(value);
                let mut path = match &val_taint {
                    TaintState::Tainted { source_name, .. } => {
                        vec![
                            format!("source: {}", source_name),
                            format!("reassigned to '{}'", target),
                        ]
                    }
                    TaintState::Sanitized { sanitizer, .. } => {
                        vec![
                            format!("sanitized via '{}'", sanitizer),
                            format!("reassigned to '{}'", target),
                        ]
                    }
                    TaintState::Clean => vec![format!("clean value reassigned to '{}'", target)],
                };
                if let Some(s) = step {
                    path.push(s);
                }
                self.env.assign(target, val_taint, path);
            }
            Statement::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                let (_cond_taint, _) = self.eval_expr_taint(cond);
                let base_env = self.env.clone();

                // Branch 1: then block
                self.env = base_env.clone();
                self.analyze_block(then_block);
                let then_env = self.env.clone();

                // Branch 2: else block (or fallthrough to base if none)
                self.env = base_env.clone();
                if let Some(eb) = else_block {
                    self.analyze_block(eb);
                }
                let else_env = self.env.clone();

                // Join branch environments into base environment
                self.env = TaintEnv::merge(base_env, &then_env, &else_env);
            }
            Statement::While { cond, body, .. } => {
                let (_cond_taint, _) = self.eval_expr_taint(cond);

                // Fixpoint iteration for loop body:
                // Loops can carry taint across iterations (e.g. a = b; b = read_i32();).
                let prev_recording = self.record_findings;
                self.record_findings = false;

                for _ in 0..5 {
                    let pre_iter = self.env.clone();
                    self.analyze_block(body);
                    let post_iter = self.env.clone();
                    self.env = TaintEnv::merge(pre_iter.clone(), &post_iter, &pre_iter);

                    // Check if taint state stabilized
                    if self.env.flattened() == pre_iter.flattened() {
                        break;
                    }
                }

                // Final pass with finding recording enabled
                self.record_findings = prev_recording;
                self.analyze_block(body);
            }
            Statement::Return { value, .. } => {
                if let Some(v) = value {
                    self.eval_expr_taint(v);
                }
            }
            Statement::Expr(e) => {
                self.eval_expr_taint(e);
            }
        }
    }

    fn eval_expr_taint(&mut self, expr: &Expr) -> (TaintState, Option<String>) {
        match expr {
            Expr::Integer(_, _) | Expr::Boolean(_, _) => (TaintState::Clean, None),
            Expr::Variable(name, _) => {
                let state = self.env.get(name).cloned().unwrap_or(TaintState::Clean);
                let step = self
                    .env
                    .get_steps(name)
                    .and_then(|s| s.last().cloned())
                    .unwrap_or_else(|| format!("var '{}'", name));
                (state, Some(step))
            }
            Expr::Binary { lhs, rhs, op, .. } => {
                let (l_taint, _) = self.eval_expr_taint(lhs);
                let (r_taint, _) = self.eval_expr_taint(rhs);

                match (&l_taint, &r_taint) {
                    (TaintState::Tainted { .. }, _) => (
                        l_taint,
                        Some(format!("binary op {:?} with tainted left", op)),
                    ),
                    (_, TaintState::Tainted { .. }) => (
                        r_taint,
                        Some(format!("binary op {:?} with tainted right", op)),
                    ),
                    (TaintState::Sanitized { .. }, _) => {
                        (l_taint, Some(format!("binary op {:?}", op)))
                    }
                    (_, TaintState::Sanitized { .. }) => {
                        (r_taint, Some(format!("binary op {:?}", op)))
                    }
                    _ => (TaintState::Clean, None),
                }
            }
            Expr::Unary { expr, op, .. } => {
                let (inner_taint, _) = self.eval_expr_taint(expr);
                (inner_taint, Some(format!("unary op {:?}", op)))
            }
            Expr::Call { callee, args, span } => {
                // Taint source: read_i32() explicitly marked as mocked guest runtime input
                if callee == "read_i32" {
                    return (
                        TaintState::Tainted {
                            source_name: "read_i32() [mocked runtime input]".to_string(),
                            source_span: *span,
                        },
                        Some("called read_i32() (untrusted host input fixture)".to_string()),
                    );
                }

                // Certified sanitizer: sanitize_i32()
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

                // Sensitive sink: print_i32, print_bool
                if matches!(callee.as_str(), "print_i32" | "print_bool") && !args.is_empty() {
                    let arg = &args[0];
                    let (arg_taint, _) = self.eval_expr_taint(arg);
                    let key = (
                        callee.clone(),
                        format!("{:?}", arg_taint),
                        span.start_line,
                        span.start_col,
                    );

                    if self.record_findings && !self.recorded_keys.contains(&key) {
                        self.recorded_keys.insert(key);
                        match arg_taint {
                            TaintState::Tainted {
                                source_name,
                                source_span: _,
                            } => {
                                let path = vec![
                                    format!("Source: {}", source_name),
                                    "Propagated into call argument".to_string(),
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
