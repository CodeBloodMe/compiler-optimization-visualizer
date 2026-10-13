use std::collections::{HashMap, HashSet};
use wasm_encoder::{
    CodeSection, ExportKind, ExportSection, Function, FunctionSection, ImportSection, Instruction,
    MemorySection, MemoryType, Module, TypeSection, ValType,
};
use wasmparser::{Validator, WasmFeatures};

use crate::ast::*;
use crate::source::{Diagnostic, Span};
use crate::types::Type;

pub struct WasmCodegen {
    function_indices: HashMap<String, u32>,
    #[allow(dead_code)]
    function_types: HashMap<String, u32>,
    #[allow(dead_code)]
    imported_functions: Vec<(String, String, u32)>, // (module, field, type_idx)
    next_func_idx: u32,
    next_type_idx: u32,
}

impl WasmCodegen {
    pub fn new() -> Self {
        Self {
            function_indices: HashMap::new(),
            function_types: HashMap::new(),
            imported_functions: Vec::new(),
            next_func_idx: 0,
            next_type_idx: 0,
        }
    }
}

impl Default for WasmCodegen {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmCodegen {
    pub fn compile(program: &Program) -> Result<Vec<u8>, Diagnostic> {
        let mut codegen = WasmCodegen::new();
        codegen.generate(program)
    }

    fn generate(&mut self, program: &Program) -> Result<Vec<u8>, Diagnostic> {
        let mut module = Module::new();
        let mut types = TypeSection::new();
        let mut imports = ImportSection::new();
        let mut functions = FunctionSection::new();
        let mut exports = ExportSection::new();
        let mut codes = CodeSection::new();

        // 0. Collect all host functions actually used in the program
        let mut used_calls = HashSet::new();
        for f in &program.functions {
            Self::collect_calls_in_block(&f.body, &mut used_calls);
        }

        let has_print_i32 = used_calls.contains("print_i32");
        let has_print_bool = used_calls.contains("print_bool");
        let has_read_i32 = used_calls.contains("read_i32");
        let has_sanitize_i32 = used_calls.contains("sanitize_i32");

        // 1. Register host import types and imports only for actually used functions
        let mut print_type_idx = None;
        if has_print_i32 || has_print_bool {
            let idx = self.next_type_idx;
            types.ty().function(vec![ValType::I32], vec![]);
            self.next_type_idx += 1;
            print_type_idx = Some(idx);
        }

        let mut read_type_idx = None;
        if has_read_i32 {
            let idx = self.next_type_idx;
            types.ty().function(vec![], vec![ValType::I32]);
            self.next_type_idx += 1;
            read_type_idx = Some(idx);
        }

        let mut sanitize_type_idx = None;
        if has_sanitize_i32 {
            let idx = self.next_type_idx;
            types.ty().function(vec![ValType::I32], vec![ValType::I32]);
            self.next_type_idx += 1;
            sanitize_type_idx = Some(idx);
        }

        if has_print_i32 {
            imports.import(
                "aegis_host",
                "print_i32",
                wasm_encoder::EntityType::Function(print_type_idx.unwrap()),
            );
            self.function_indices
                .insert("print_i32".to_string(), self.next_func_idx);
            self.next_func_idx += 1;
        }

        if has_print_bool {
            imports.import(
                "aegis_host",
                "print_bool",
                wasm_encoder::EntityType::Function(print_type_idx.unwrap()),
            );
            self.function_indices
                .insert("print_bool".to_string(), self.next_func_idx);
            self.next_func_idx += 1;
        }

        if has_read_i32 {
            imports.import(
                "aegis_host",
                "read_i32",
                wasm_encoder::EntityType::Function(read_type_idx.unwrap()),
            );
            self.function_indices
                .insert("read_i32".to_string(), self.next_func_idx);
            self.next_func_idx += 1;
        }

        if has_sanitize_i32 {
            imports.import(
                "aegis_host",
                "sanitize_i32",
                wasm_encoder::EntityType::Function(sanitize_type_idx.unwrap()),
            );
            self.function_indices
                .insert("sanitize_i32".to_string(), self.next_func_idx);
            self.next_func_idx += 1;
        }

        // 2. Register user functions
        for f in &program.functions {
            let params_val: Vec<ValType> = f
                .params
                .iter()
                .map(|p| match p.ty {
                    Type::I32 | Type::Bool => ValType::I32,
                    Type::Void => unreachable!(),
                })
                .collect();

            let results_val: Vec<ValType> = match f.return_type {
                Type::I32 | Type::Bool => vec![ValType::I32],
                Type::Void => vec![],
            };

            let type_idx = self.next_type_idx;
            types.ty().function(params_val, results_val);
            self.next_type_idx += 1;

            functions.function(type_idx);
            self.function_indices
                .insert(f.name.clone(), self.next_func_idx);
            self.next_func_idx += 1;
        }

        // 3. Setup linear memory
        let mut memory = MemorySection::new();
        memory.memory(MemoryType {
            minimum: 1,
            maximum: Some(16),
            memory64: false,
            shared: false,
            page_size_log2: None,
        });

        // 4. Exports
        for f in &program.functions {
            let idx = *self.function_indices.get(&f.name).unwrap();
            exports.export(&f.name, ExportKind::Func, idx);
        }
        exports.export("memory", ExportKind::Memory, 0);

        // 5. Generate function bodies
        for f in &program.functions {
            let code = self.compile_function(f)?;
            codes.function(&code);
        }

        module.section(&types);
        if !imports.is_empty() {
            module.section(&imports);
        }
        module.section(&functions);
        module.section(&memory);
        module.section(&exports);
        module.section(&codes);

        let wasm_bytes = module.finish();

        // 6. Validate Wasm binary via wasmparser
        let mut validator = Validator::new_with_features(WasmFeatures::default());
        if let Err(err) = validator.validate_all(&wasm_bytes) {
            return Err(Diagnostic::error(
                format!("WebAssembly binary validation error: {}", err),
                Span::point(1, 1),
            ));
        }

        Ok(wasm_bytes)
    }

    fn compile_function(&self, f: &FunctionDecl) -> Result<Function, Diagnostic> {
        let mut local_map: HashMap<String, u32> = HashMap::new();
        let mut next_local = 0;

        for p in &f.params {
            local_map.insert(p.name.clone(), next_local);
            next_local += 1;
        }

        // Collect all declared local variables in function body
        let mut extra_locals = Vec::new();
        Self::collect_locals_in_block(&f.body, &mut extra_locals);

        let mut local_types = Vec::new();
        for (var_name, _var_ty) in &extra_locals {
            if !local_map.contains_key(var_name) {
                local_map.insert(var_name.clone(), next_local);
                next_local += 1;
                local_types.push((1, ValType::I32)); // count, type
            }
        }

        let mut func = Function::new(local_types);

        // Compile statements
        self.compile_block(&f.body, &local_map, &mut func)?;

        // Ensure default return if not returned
        match f.return_type {
            Type::I32 | Type::Bool => {
                func.instruction(&Instruction::I32Const(0));
            }
            Type::Void => {}
        }
        func.instruction(&Instruction::End);

        Ok(func)
    }

    fn collect_locals_in_block(block: &Block, locals: &mut Vec<(String, Type)>) {
        for stmt in &block.statements {
            match stmt {
                Statement::Let { name, ty, .. } => {
                    locals.push((name.clone(), ty.unwrap_or(Type::I32)));
                }
                Statement::If {
                    then_block,
                    else_block,
                    ..
                } => {
                    Self::collect_locals_in_block(then_block, locals);
                    if let Some(eb) = else_block {
                        Self::collect_locals_in_block(eb, locals);
                    }
                }
                Statement::While { body, .. } => {
                    Self::collect_locals_in_block(body, locals);
                }
                _ => {}
            }
        }
    }

    fn collect_calls_in_block(block: &Block, calls: &mut HashSet<String>) {
        for stmt in &block.statements {
            Self::collect_calls_in_stmt(stmt, calls);
        }
    }

    fn collect_calls_in_stmt(stmt: &Statement, calls: &mut HashSet<String>) {
        match stmt {
            Statement::Let { init, .. } => {
                Self::collect_calls_in_expr(init, calls);
            }
            Statement::Assign { value, .. } => {
                Self::collect_calls_in_expr(value, calls);
            }
            Statement::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                Self::collect_calls_in_expr(cond, calls);
                Self::collect_calls_in_block(then_block, calls);
                if let Some(eb) = else_block {
                    Self::collect_calls_in_block(eb, calls);
                }
            }
            Statement::While { cond, body, .. } => {
                Self::collect_calls_in_expr(cond, calls);
                Self::collect_calls_in_block(body, calls);
            }
            Statement::Return { value, .. } => {
                if let Some(v) = value {
                    Self::collect_calls_in_expr(v, calls);
                }
            }
            Statement::Expr(e) => {
                Self::collect_calls_in_expr(e, calls);
            }
        }
    }

    fn collect_calls_in_expr(expr: &Expr, calls: &mut HashSet<String>) {
        match expr {
            Expr::Call { callee, args, .. } => {
                calls.insert(callee.clone());
                for a in args {
                    Self::collect_calls_in_expr(a, calls);
                }
            }
            Expr::Binary { lhs, rhs, .. } => {
                Self::collect_calls_in_expr(lhs, calls);
                Self::collect_calls_in_expr(rhs, calls);
            }
            Expr::Unary { expr, .. } => {
                Self::collect_calls_in_expr(expr, calls);
            }
            Expr::Block(b) => {
                Self::collect_calls_in_block(b, calls);
            }
            _ => {}
        }
    }

    fn compile_block(
        &self,
        block: &Block,
        locals: &HashMap<String, u32>,
        func: &mut Function,
    ) -> Result<(), Diagnostic> {
        for stmt in &block.statements {
            self.compile_statement(stmt, locals, func)?;
        }
        Ok(())
    }

    fn compile_statement(
        &self,
        stmt: &Statement,
        locals: &HashMap<String, u32>,
        func: &mut Function,
    ) -> Result<(), Diagnostic> {
        match stmt {
            Statement::Let { name, init, .. } => {
                self.compile_expr(init, locals, func)?;
                let idx = *locals.get(name).unwrap();
                func.instruction(&Instruction::LocalSet(idx));
                Ok(())
            }
            Statement::Assign { target, value, .. } => {
                self.compile_expr(value, locals, func)?;
                let idx = *locals.get(target).unwrap();
                func.instruction(&Instruction::LocalSet(idx));
                Ok(())
            }
            Statement::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                self.compile_expr(cond, locals, func)?;
                func.instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
                self.compile_block(then_block, locals, func)?;
                if let Some(eb) = else_block {
                    func.instruction(&Instruction::Else);
                    self.compile_block(eb, locals, func)?;
                }
                func.instruction(&Instruction::End);
                Ok(())
            }
            Statement::While { cond, body, .. } => {
                // Loop construct in WebAssembly:
                // block $exit {
                //   loop $cont {
                //     <cond>
                //     i32.eqz
                //     br_if $exit
                //     <body>
                //     br $cont
                //   }
                // }
                func.instruction(&Instruction::Block(wasm_encoder::BlockType::Empty)); // block 0 (exit)
                func.instruction(&Instruction::Loop(wasm_encoder::BlockType::Empty)); // loop 1 (continue)

                self.compile_expr(cond, locals, func)?;
                func.instruction(&Instruction::I32Eqz);
                func.instruction(&Instruction::BrIf(1)); // break to block 0

                self.compile_block(body, locals, func)?;
                func.instruction(&Instruction::Br(0)); // loop again

                func.instruction(&Instruction::End); // end loop
                func.instruction(&Instruction::End); // end block
                Ok(())
            }
            Statement::Return { value, .. } => {
                if let Some(expr) = value {
                    self.compile_expr(expr, locals, func)?;
                }
                func.instruction(&Instruction::Return);
                Ok(())
            }
            Statement::Expr(expr) => {
                self.compile_expr(expr, locals, func)?;
                // If expression produced a value that's not consumed, drop it
                match expr {
                    Expr::Call { callee, .. } => {
                        if callee != "print_i32" && callee != "print_bool" {
                            func.instruction(&Instruction::Drop);
                        }
                    }
                    Expr::Integer(_, _)
                    | Expr::Boolean(_, _)
                    | Expr::Variable(_, _)
                    | Expr::Binary { .. }
                    | Expr::Unary { .. } => {
                        func.instruction(&Instruction::Drop);
                    }
                    _ => {}
                }
                Ok(())
            }
        }
    }

    fn compile_expr(
        &self,
        expr: &Expr,
        locals: &HashMap<String, u32>,
        func: &mut Function,
    ) -> Result<(), Diagnostic> {
        match expr {
            Expr::Integer(v, _) => {
                func.instruction(&Instruction::I32Const(*v as i32));
                Ok(())
            }
            Expr::Boolean(b, _) => {
                func.instruction(&Instruction::I32Const(if *b { 1 } else { 0 }));
                Ok(())
            }
            Expr::Variable(name, _) => {
                let idx = *locals.get(name).unwrap();
                func.instruction(&Instruction::LocalGet(idx));
                Ok(())
            }
            Expr::Binary { op, lhs, rhs, .. } => {
                self.compile_expr(lhs, locals, func)?;
                self.compile_expr(rhs, locals, func)?;
                match op {
                    BinaryOp::Add => func.instruction(&Instruction::I32Add),
                    BinaryOp::Sub => func.instruction(&Instruction::I32Sub),
                    BinaryOp::Mul => func.instruction(&Instruction::I32Mul),
                    BinaryOp::Div => func.instruction(&Instruction::I32DivS),
                    BinaryOp::Rem => func.instruction(&Instruction::I32RemS),
                    BinaryOp::Eq => func.instruction(&Instruction::I32Eq),
                    BinaryOp::Neq => func.instruction(&Instruction::I32Ne),
                    BinaryOp::Lt => func.instruction(&Instruction::I32LtS),
                    BinaryOp::Lte => func.instruction(&Instruction::I32LeS),
                    BinaryOp::Gt => func.instruction(&Instruction::I32GtS),
                    BinaryOp::Gte => func.instruction(&Instruction::I32GeS),
                    BinaryOp::And => func.instruction(&Instruction::I32And),
                    BinaryOp::Or => func.instruction(&Instruction::I32Or),
                };
                Ok(())
            }
            Expr::Unary { op, expr, .. } => {
                match op {
                    UnaryOp::Neg => {
                        func.instruction(&Instruction::I32Const(0));
                        self.compile_expr(expr, locals, func)?;
                        func.instruction(&Instruction::I32Sub);
                    }
                    UnaryOp::Not => {
                        self.compile_expr(expr, locals, func)?;
                        func.instruction(&Instruction::I32Eqz);
                    }
                }
                Ok(())
            }
            Expr::Call { callee, args, .. } => {
                for arg in args {
                    self.compile_expr(arg, locals, func)?;
                }
                let func_idx = *self.function_indices.get(callee).unwrap();
                func.instruction(&Instruction::Call(func_idx));
                Ok(())
            }
            Expr::Block(block) => {
                self.compile_block(block, locals, func)?;
                Ok(())
            }
        }
    }
}
