# AEGIS: Security-First, Resource-Bounded Compiler & Optimization Visualizer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust: 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Target: WebAssembly](https://img.shields.io/badge/Target-WebAssembly-blueviolet.svg)](https://webassembly.org/)
[![Runtime: Wasmtime](https://img.shields.io/badge/Runtime-Wasmtime-blue.svg)](https://wasmtime.dev/)

**Aegis** is a statically typed programming language and compiler targeting WebAssembly, integrating capability-based access control, deterministic resource bounding (fuel budgeting and linear memory ceilings), static information flow (taint) tracking, and security-aware intermediate representation (IR) optimization passes.

---

## 📌 Project Overview & Design Principles

Traditional systems and language runtimes frequently suffer from:
1. **Unchecked Ambient Authority:** Programs implicitly gain access to host filesystems, network interfaces, and consoles without explicit declarations.
2. **Denial-of-Service / Unbounded Loops:** Uncontrolled execution consumes unlimited CPU cycles and host memory.
3. **Security-Blind Optimization:** Compilers optimize code for throughput while disregarding security boundaries, taint propagation, or trap behavior.

**Aegis addresses these challenges through a unified compilation and runtime pipeline:**
- **Explicit Capability Contracts:** Modules must declare host privileges in source headers (e.g., `requires console.write;`, `requires host.read;`). The compiler enforces these declarations at compile time, and the runtime verifies them prior to execution.
- **On-Demand Host Imports:** WebAssembly import entries are generated *only* for host functions actually called by the program. Pure compute modules contain zero host imports and execute under restrictive policies where all host access is disabled.
- **Deterministic Resource Budgets:** Programs execute in an isolated Wasmtime environment with precise fuel accounting and memory limits. Fuel exhaustion terminates execution deterministically.
- **Static Taint Analysis:** Information flow tracking with lexical scope stacks, branch state merging, and loop fixpoint iteration tracks untrusted inputs to sensitive sinks.
- **Trap-Preserving IR Optimization:** Constant folding and algebraic simplification adhere to two's complement wrapping arithmetic and strictly preserve WebAssembly runtime traps (division by zero, `i32::MIN / -1`).

---

## 🏗️ Compiler Architecture

```text
  +-------------------------------------------------------+
  |              AegisLang Source Program                 |
  | (module, requires <cap>;, functions, statements, expr)|
  +---------------------------+---------------------------+
                              |
                              v
                      [ Lexical Analysis ]  (source.rs, lexer.rs)
                              |
                              v
                   [ Recursive-Descent Parser ] (ast.rs, parser.rs)
                              |
                              v
             [ Semantic Analysis & Symbol Resolution ] (semantics.rs)
               - Type Checking (i32, bool, void)
               - Immutability & Scope Enforcement
               - Capability Requirement Checking
               - Return Path Completeness Verification
               - Integer Literal Range Validation
                              |
                              v
             [ Custom Typed Intermediate Representation ] (ir.rs)
               - Basic Block Lowering & CFG Construction
               - Static IR Invariant Verification
                              |
              +---------------+---------------+
              |                               |
              v                               v
    [ Static Taint Engine ]       [ Security-Aware IR Optimizer ]
    - Lexical Scope Stacks        - Constant Folding (Wrapping)
    - Sound Branch State Merging  - Trap Preservation (Div/Rem)
    - Loop Fixpoint Iteration     - Algebraic Simplification
    - Sanitizer Recognition       - Reachability-Based Dead Code Elimination
              |                               |
              +---------------+---------------+
                              |
                              v
                 [ WebAssembly Code Generator ] (codegen.rs)
                   - Minimal Import Section (Used Hosts Only)
                   - Custom Binary Emitter (wasm-encoder)
                   - Binary Validation (wasmparser)
                              |
                              v
               [ Wasmtime Resource-Bounded Runtime ] (runtime.rs, policy.rs)
                 - TOML Policy Enforcement (capabilities & imports)
                 - Deterministic Fuel Consumption Engine
                 - Strict Linear Memory Ceilings (Pages)
                 - Sandboxed Host Function Handlers
```

---

## 🔤 AegisLang Specification

AegisLang is a statically typed language designed for resource-bounded and capability-governed WebAssembly execution.

### Implemented Features
- **Module Declarations:** Named modules with explicit headers (`module <name>;`).
- **Capability Requirements:** Explicit required capabilities (`requires console.write;`, `requires host.read;`).
- **Static Types:** `i32` (32-bit signed integer), `bool` (boolean), `void` (function return).
- **Variable Bindings:** Immutable (`let x: i32 = ...;`) and mutable (`let mut y: i32 = ...;`).
- **Control Flow:** `if / else` branching, `while` loops, and return statements.
- **Host Functions:** Privileged host builtins `print_i32(i32)`, `print_bool(bool)`, `read_i32() -> i32`, and certified sanitizer `sanitize_i32(i32) -> i32`.
- **Wasm Codegen & Validation:** Generates valid WebAssembly bytecode validated with `wasmparser`.

### Example Program
```rust
module secure_adder;

// Capability requirement: grants permission to invoke console output
requires console.write;

fn main() -> i32 {
    let a: i32 = 10;
    let b: i32 = 20;
    let result: i32 = a + b;
    print_i32(result);
    return 0;
}
```

---

## 🔒 Verified Security Properties

Aegis has been validated with regression and integration test suites covering the following properties:

1. **Capability Enforcement at Compile Time:**
   - Calling privileged host functions (`print_i32`, `read_i32`) without declaring their capability (`console.write`, `host.read`) is rejected during semantic analysis.
2. **Capability Enforcement at Runtime:**
   - If a host capability is revoked in the runtime TOML policy, the runtime halts execution prior to invocation with `PolicyViolation` and zero fuel consumed.
3. **Minimal WebAssembly Imports:**
   - Code generation scans the AST to import *only* host functions actually invoked.
   - Pure computational modules emit zero host imports and run successfully under restrictive policies where all capabilities are disabled.
4. **Sound Branch-State Merging in Taint Analysis:**
   - If an untrusted source taints a variable in either branch of an `if-else` statement, the merge state retains the taint and alerts on downstream sensitive sinks.
5. **Loop Carried Taint Fixpoint Iteration:**
   - Taint carried across loop iterations (e.g., `x = y; y = read_i32();`) is tracked via iterative fixpoint analysis.
6. **Lexical Scope Isolation:**
   - Shadowed variables inside inner scopes do not pollute clean outer variables of the same name, preventing false positives.
7. **Arithmetic Semantics and Trap Preservation:**
   - Compile-time constant folding uses two's complement wrapping (`wrapping_add`, `wrapping_sub`, `wrapping_mul`), matching WebAssembly runtime execution (`2147483647 + 1 = -2147483648`).
   - Constant folding explicitly preserves WebAssembly traps: division by zero (`x / 0`, `x % 0`) and overflow division (`i32::MIN / -1`) are not folded away into constants.
8. **Exhaustive Return Path Checking:**
   - Non-void functions must terminate with a return statement on all control-flow paths; missing returns are rejected at compile time.
9. **Integer Literal Range Validation:**
   - Literal values outside signed 32-bit integer limits (`-2147483648..=2147483647`) are rejected at compile time.
10. **Visualizer Hardening:**
    - The visualizer server binds strictly to `127.0.0.1` by default.
    - All incoming payloads are validated for size (<= 1MB), type safety, and strictly bounded parameters.
    - Policy TOML is generated using strongly typed primitives, eliminating TOML configuration injection.
    - All external compiler subprocesses run with bounded timeouts (10s).

---

## 📊 Measured Benchmark Results

All metrics below are generated reproducibly by the automated benchmark harness ([`benchmarks/run_benchmarks.py`](benchmarks/run_benchmarks.py)) and recorded in [`benchmarks/benchmark_results.json`](benchmarks/benchmark_results.json):

| Metric | Measured Value | Methodology / Description |
|:---|:---:|:---|
| **Compilation Latency** | **114.8 ms** | Average of 10 runs (Lex $\to$ AST $\to$ IR $\to$ Codegen $\to$ Wasm validation) |
| **Static Taint Analysis Latency** | **14.4 ms** | Average of 10 runs on `taint_vulnerability.aegis` |
| **Vulnerability Detection Rate** | **100.0%** | 3 / 3 true positive cases detected in expanded evaluation corpus |
| **False Positive Rate** | **0.0%** | 0 / 5 clean programs falsely flagged in evaluation corpus |
| **Code Size Reduction** | **12.9%** | 124 bytes (unoptimized) $\to$ 108 bytes (optimized) on `math_opt.aegis` |
| **Execution Fuel Reduction** | **44.4%** | 18 fuel units (unoptimized) $\to$ 10 fuel units (optimized) on `math_opt.aegis` |
| **Resource Limit Enforcement** | **Deterministic (Exit 3)** | Execution terminates cleanly when fuel budget reaches 0 |

### Evaluation Corpus Breakdown
The evaluation corpus contains 8 labeled test programs:
1. `taint_vulnerability.aegis`: Direct untrusted input into sensitive sink (**True Positive**)
2. `branch_leak.aegis`: Branch-merged untrusted input into sensitive sink (**True Positive**)
3. `loop_carried_taint.aegis`: Loop-carried untrusted input into sensitive sink (**True Positive**)
4. `taint_sanitized.aegis`: Certified sanitizer before sensitive sink (**True Negative**)
5. `both_sanitized.aegis`: Exhaustively sanitized branches before sink (**True Negative**)
6. `scoped_shadow_clean.aegis`: Inner shadowed variable does not pollute outer variable (**True Negative**)
7. `hello.aegis`: Clean deterministic computation (**True Negative**)
8. `loop_fuel.aegis`: Clean iterative computation (**True Negative**)

---

## ⚠️ Remaining Limitations

1. **Type System Scope:** AegisLang currently supports `i32`, `bool`, and `void`. Floating-point arithmetic (`f32`, `f64`), arrays, pointers, strings, and user-defined structs are not yet implemented.
2. **Intra-Procedural Taint Analysis:** Static taint analysis currently operates within single function bodies. Inter-procedural call-graph information flow across user-defined functions is planned for a future release.
3. **LALRPOP Grammar Status:** The grammar specification in `src/aegis.lalrpop` is a formal non-executable LR(1) reference draft aligned with the AST. The production compiler executes the handwritten recursive-descent parser in `src/parser.rs` for detailed syntax diagnostics.
4. **Mocked Host Input in Tests:** Runtime input fixture `read_i32()` currently returns a deterministic integer (`42`) for automated reproducible testing rather than interacting with interactive terminal stdin.
5. **Visualizer Subprocess Model:** The visualizer server invokes the compiler via local subprocesses rather than running WebAssembly modules directly in-browser.

---

## 💻 Command-Line Interface (CLI)

```bash
# 1. Type-check, check capabilities, and verify return paths
aegis check examples/hello.aegis

# 2. Compile AegisLang source to WebAssembly binary
aegis compile examples/hello.aegis -o build/hello.wasm

# 3. Compile with security-aware IR optimizations enabled
aegis compile examples/math_opt.aegis --opt -o build/math_opt.wasm

# 4. Inspect WebAssembly binary sections, imports, and exports
aegis inspect build/hello.wasm

# 5. Run WebAssembly binary under runtime policy and fuel constraints
aegis run build/hello.wasm --policy policies/default.toml

# 6. Perform static taint analysis and information flow verification
aegis analyze examples/taint_vulnerability.aegis
```

---

## 🖥️ Running the Visualizer Dashboard

```bash
python visualizer/server.py
```
By default, the server binds to `http://127.0.0.1:8080`.

---

## 🧪 Testing and Verification

Run the full automated test suite:
```bash
cargo test
cargo clippy --all-targets
cargo fmt --check
python tests/test_visualizer.py
python benchmarks/run_benchmarks.py
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
