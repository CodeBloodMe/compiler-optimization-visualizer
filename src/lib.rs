pub mod ast;
pub mod codegen;
pub mod ir;
pub mod lexer;
pub mod optimizer;
pub mod parser;
pub mod policy;
pub mod runtime;
pub mod security;
pub mod semantics;
pub mod source;
pub mod types;

use ast::Program;
use codegen::WasmCodegen;
use lexer::Lexer;
use optimizer::Optimizer;
use parser::Parser;
use policy::AegisPolicy;
use runtime::{AegisRuntime, ExecutionResult};
use security::{TaintAnalyzer, TaintReport};
use semantics::SemanticAnalyzer;
use source::Diagnostic;

pub fn check_source(source: &str) -> Result<Program, Diagnostic> {
    let mut lexer = Lexer::new(source);
    let tokens = lexer.tokenize()?;
    let mut parser = Parser::new(tokens);
    let program = parser.parse_program()?;

    let mut analyzer = SemanticAnalyzer::new();
    analyzer.analyze_program(&program)?;

    Ok(program)
}

pub fn compile_source(source: &str, optimize: bool) -> Result<Vec<u8>, Diagnostic> {
    let program = check_source(source)?;
    let target_program = if optimize {
        let mut opt = Optimizer::new();
        opt.optimize_program(&program)
    } else {
        program
    };

    WasmCodegen::compile(&target_program)
}

pub fn analyze_source(source: &str) -> Result<TaintReport, Diagnostic> {
    let program = check_source(source)?;
    let report = TaintAnalyzer::analyze_program(&program);
    Ok(report)
}

pub fn execute_source(source: &str, policy: &AegisPolicy) -> Result<ExecutionResult, Diagnostic> {
    let wasm_bytes = compile_source(source, false)?;
    let rt = AegisRuntime::new().map_err(|e| Diagnostic::error(e.to_string(), source::Span::point(1, 1)))?;
    Ok(rt.execute(&wasm_bytes, policy))
}
