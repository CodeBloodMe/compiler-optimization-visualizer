# AEGIS: Security-First, Resource-Bounded Compiler & Optimization Visualizer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust: 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Target: WebAssembly](https://img.shields.io/badge/Target-WebAssembly-blueviolet.svg)](https://webassembly.org/)
[![Runtime: Wasmtime](https://img.shields.io/badge/Runtime-Wasmtime-blue.svg)](https://wasmtime.dev/)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-brightgreen.svg)](.github/workflows/ci.yml)

**Aegis** is an advanced, security-first compiler and WebAssembly execution environment designed to enforce principle-of-least-privilege host capability access, deterministic resource bounding (fuel budgeting and linear memory ceilings), and static taint flow verification.

Rather than treating security as an external sandbox wrapper or optimization as a security-agnostic black box, Aegis tightly integrates capability declarations, static information flow tracking, and security-aware IR optimization directly into the compilation and execution pipeline.

---

## 📌 Core Research Motivation

Traditional language toolchains and compiler suites (e.g., C/C++ via Clang/LLVM, standard Rust) separate code generation from execution policy:
1. **Unchecked Ambient Authority:** Code implicitly accesses host APIs (file system, network, standard I/O) without declared contracts.
2. **Denial-of-Service Vulnerabilities:** Unbounded recursion or infinite loops consume host CPU cores and memory indefinitely.
3. **Security-Blind Transformations:** Compilers optimize for speed while disregarding taint leakage, side-channel amplification, or security invariants.

**Aegis solves this via a unified pipeline:**
- **Explicit Capability Contracts:** Modules must explicitly declare required host privileges (e.g., `requires console.write;`). The runtime verifies and refuses to invoke binaries demanding unauthorized capabilities.
- **Deterministic Resource Budgets:** Programs run inside an isolated Wasmtime runtime with precise fuel counters and linear memory clamps. Fuel exhaustion terminates execution deterministically.
- **Static Taint Tracking:** The semantic pipeline traces data flow from untrusted host inputs (sources) through assignments and branches into privileged operations (sinks), identifying vulnerabilities before code generation.
- **Security-Aware IR Optimization:** Redundant computations are folded and dead branches eliminated *without* mutating security assertions or crossing capability boundaries.

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
                              |
                              v
             [ Custom Typed Intermediate Representation ] (ir.rs)
               - Control-Flow Lowering (Basic Blocks)
               - Static IR Verifier & Invariant Checks
                              |
              +---------------+---------------+
              |                               |
              v                               v
    [ Static Taint Engine ]       [ Security-Aware Optimizer ]
    - Source/Sanitizer/Sink       - Constant Folding & Propagation
    - Flow Path Reconstruction    - Algebraic Simplification
    - Vulnerability Reporting     - Safe Dead-Code Elimination
              |                               |
              +---------------+---------------+
                              |
                              v
                 [ WebAssembly Code Generator ] (codegen.rs)
                   - Custom Binary Emitter (wasm-encoder)
                   - Import / Export Tables
                   - Bytecode Validation (wasmparser)
                              |
                              v
               [ Wasmtime Resource-Bounded Runtime ] (runtime.rs, policy.rs)
                 - TOML Policy Enforcement (capabilities & imports)
                 - Deterministic Fuel Consumption Engine
                 - Strict Linear Memory Ceilings (Pages)
                 - Isolated Host Capability Interceptors
```

---

## 🔤 AegisLang Specification

AegisLang is a statically typed language tailored for resource-constrained, capability-secured modules.

### Syntax Features
- **Modules & Capabilities:** Explicit module name and `requires <capability>;` declarations.
- **Functions:** Typed parameters and explicit return types (`-> i32`, `-> bool`, `-> void`).
- **Variables:** Explicitly immutable (`let x: i32 = ...;`) or mutable (`let mut y: i32 = ...;`).
- **Control Flow:** `if / else` branching, `while` loops, and structured `return`.
- **Host Builtins:** Isolated builtins including `print_i32`, `print_bool`, `read_i32`, and `sanitize_i32`.

### Example Program
```rust
module secure_adder;

// Capability requirement: grants permission to invoke console output
requires console.write;

fn main() -> i32 {
    let a: i32 = 10;
    let b: i32 = 25;
    let sum: i32 = a + b;
    
    // Privileged call checked at compile-time and runtime
    print_i32(sum);
    return sum;
}
```

---

## 🛡️ Capability-Based Access Control

Aegis implements dual-phase capability enforcement:

1. **Compile-Time Phase (`semantics.rs`):**
   - The compiler verifies that any call to privileged functions (e.g., `print_i32` requiring `console.write`) is accompanied by an explicit `requires console.write;` declaration in the source.
   - If undeclared, the compiler rejects the program with an informative diagnostic.

2. **Runtime Policy Phase (`runtime.rs`, `policy.rs`):**
   - The host provides a TOML policy file (e.g., `policies/default.toml` or `policies/restricted.toml`).
   - Before instantiation, Aegis inspects the WebAssembly module's import table.
   - If the module requires `console.write` but the runtime policy sets `console_write = false`, execution is halted **prior to invocation** with exit code `2` (`PolicyViolation`).

### Example Policy (`policies/default.toml`)
```toml
[capabilities]
console_write = true
host_read = true

[resources]
initial_fuel = 1000000
max_memory_pages = 16

[security]
strict_imports = true
deny_unknown_imports = true
```

---

## ⚡ Resource-Bounded Execution Engine

Aegis embeds **Wasmtime 49.0** configured with deterministic execution limits:

- **Fuel Metering:** Instructions consume deterministic fuel units. Programs in unbounded loops exhaust their fuel budget and terminate safely with exit code `-1` (`FuelExhausted`).
- **Linear Memory Clamping:** Guest memory growth is bounded to configured page limits (64 KiB per page), protecting the host against memory exhaustion.
- **Runtime Error Classification:**
  - `PolicyViolation` (Exit Code 2)
  - `FuelExhausted` (Exit Code 3 / -1)
  - `MemoryLimitExceeded` (Exit Code 4)
  - `UnknownImport` (Exit Code 5)
  - `Trap` (Exit Code 6)
  - `MalformedBinary` (Exit Code 7)

---

## 🔍 Static Taint Analysis

The Aegis security engine (`src/security.rs`) models information flow:
- **Taint Sources:** Operations introducing untrusted guest or host data (e.g., `read_i32()`).
- **Propagation Rules:** Taint propagates across binary arithmetic expressions, variable assignments, and join points.
- **Sanitizers:** Certified host transforms (e.g., `sanitize_i32(val)`) cleanse tainted values.
- **Sensitive Sinks:** Privileged or observable outputs (e.g., `print_i32(sink)`).

If tainted data reaches a sensitive sink without passing through a sanitizer, Aegis flags the violation with exact file, line, and column coordinates, displaying the entire causal trace path.

---

## 🚀 Security-Aware Optimization

The optimization engine (`src/optimizer.rs`) performs semantic-preserving transformations directly on the custom IR:
- **Constant Folding:** Simplifies compile-time constants (e.g., `10 + 20 * 3` $\to$ `70`).
- **Algebraic Simplification:** Eliminates identity expressions (e.g., `x + 0` $\to$ `x`, `x * 1` $\to$ `x`, `x * 0` $\to$ `0`).
- **Safe Dead Code Elimination:** Prunes unreachable basic blocks while strictly preserving side-effecting capability calls.

### Differential Verification
All optimizations are verified with differential tests to ensure:
- Identical return codes and observable outputs.
- Substantial reduction in dynamic fuel consumption (up to 44.4% in compute kernels).
- Guaranteed preservation of security invariants.

---

## 💻 Command-Line Interface (CLI)

The `aegis` CLI exposes real compiler and runtime commands:

```bash
# 1. Type-check, symbol resolve, and verify IR without emitting code
aegis check examples/hello.aegis

# 2. Compile AegisLang source to WebAssembly binary
aegis compile examples/hello.aegis -o build/hello.wasm

# 3. Compile with security-aware optimizations enabled
aegis compile examples/math_opt.aegis --opt -o build/math_opt.wasm

# 4. Inspect WebAssembly binary sections, imports, and exports
aegis inspect build/hello.wasm

# 5. Run WebAssembly binary under runtime policy and fuel constraints
aegis run build/hello.wasm --policy policies/default.toml

# 6. Perform static taint analysis and information flow verification
aegis analyze examples/taint_vulnerability.aegis
```

---

## 📊 Empirical Benchmarks

All benchmark metrics are generated via reproducible automated runs ([`benchmarks/run_benchmarks.py`](benchmarks/run_benchmarks.py)) using actual Wasmtime execution cycles and real compiler passes:

| Benchmark / Evaluation Metric | Measurement | Description / Result |
|:---|:---:|:---|
| **Compilation Latency** | **34.8 ms** | Full pipeline (Lex $\to$ AST $\to$ IR $\to$ Codegen) |
| **Static Security Analysis** | **26.2 ms** | Complete AST & IR taint flow reconstruction |
| **Taint Vulnerability Detection Rate** | **100% (0% FP)** | Accurately identifies unsanitized flows; clears sanitized flows |
| **Optimization Fuel Reduction** | **44.4%** | 18 fuel units (unoptimized) $\to$ 10 fuel units (optimized) |
| **Binary Code Size Reduction** | **7.8%** | 205 bytes $\to$ 189 bytes |
| **Fuel Exhaustion Termination** | **Deterministic** | Infinite loop cleanly trapped when budget reaches 0 |
| **Policy Rejection Latency** | **9.8 ms** | Pre-invocation rejection of unauthorized capabilities |

---

## 🖥️ Interactive Visualizer Dashboard

A modern visualizer dashboard is included in [`visualizer/`](visualizer/) allowing interactive exploration:
- **Code Editor:** Live AegisLang editing with preloaded security test kernels.
- **Pipeline Actions:** Real-time Check, Run, Taint Analysis, and Optimization profiling.
- **Resource Controls:** Live sliders for fuel budgets, memory pages, and capability authorization toggles.
- **Optimization Diff:** Visual comparison of unoptimized vs. optimized fuel, bytecode sizes, and runtime output.
- **Empirical Metrics:** Live graphs of benchmark latency, code size savings, and security detection rates.

### Launching the Dashboard:
```bash
python visualizer/server.py
```
Then navigate to `http://localhost:8080` in your web browser.

---

## 🧪 Testing and Verification

The test suite covers full unit, integration, and security test suites:

```bash
cargo test
```

### Verified Test Cases:
- `test_valid_program_compiles`: End-to-end compilation of valid modules.
- `test_invalid_syntax_rejected`: Parser rejects malformed syntax with line/col diagnostics.
- `test_type_mismatch_rejected`: Type checker enforces strict typing (`i32` vs `bool`).
- `test_immutable_reassignment_rejected`: Enforces variable immutability guarantees.
- `test_missing_capability_rejected`: Detects and rejects missing capability requirements.
- `test_unauthorized_capability_rejected`: Runtime policy halts ungranted capabilities.
- `test_authorized_console_output`: Authorized host functions execute and capture guest output.
- `test_fuel_exhaustion_terminates`: Deterministic termination under finite fuel budgets.
- `test_malformed_wasm_rejected`: Validates binary verification against malformed Wasm byte streams.
- `test_taint_vulnerability_detected`: Accurately traces source-to-sink vulnerability paths.
- `test_taint_sanitized_flow_allowed`: Confirms certified sanitizers clear taint status.
- `test_optimization_preserves_semantics`: Verifies unoptimized and optimized code produce identical results.

---

## 📁 Repository Structure

```text
compiler-optimization-visualizer/
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI workflow
├── benchmarks/
│   ├── run_benchmarks.py        # Automated benchmark harness
│   └── benchmark_results.json   # Empirical measurement outputs
├── docs/
│   └── review 1.pdf             # Review 1 presentation slides
├── examples/
│   ├── hello.aegis              # Basic integer arithmetic and console output
│   ├── loop_fuel.aegis          # Infinite loop for resource limit testing
│   ├── math_opt.aegis           # Optimization pass benchmark program
│   ├── taint_sanitized.aegis    # Sanitized safe information flow
│   ├── taint_vulnerability.aegis# Vulnerable taint propagation test
│   └── unauthorized_cap.aegis   # Policy denial test program
├── policies/
│   ├── default.toml             # Standard policy (full capabilities & fuel)
│   ├── restricted.toml          # Restricted policy (no console.write)
│   └── low_fuel.toml            # Constrained fuel policy (500 units)
├── src/
│   ├── ast.rs                   # Abstract Syntax Tree definitions
│   ├── codegen.rs               # WebAssembly code generator (wasm-encoder)
│   ├── ir.rs                    # Custom typed IR & verifier
│   ├── lexer.rs                 # Lexer & tokenizer
│   ├── lib.rs                   # Core compiler library interface
│   ├── main.rs                  # CLI command implementation (clap)
│   ├── optimizer.rs             # Constant folding & dead code elimination
│   ├── parser.rs                # Recursive-descent parser
│   ├── policy.rs                # TOML policy parser & capability models
│   ├── runtime.rs               # Wasmtime runtime & resource bounding
│   ├── security.rs              # Static taint analysis engine
│   ├── semantics.rs             # Symbol resolution & type checker
│   ├── source.rs                # Span tracking & diagnostics
│   └── types.rs                 # Type system representations
├── tests/
│   └── integration_tests.rs     # Automated test suite (12 tests)
├── visualizer/
│   ├── app.js                   # Visualizer frontend logic
│   ├── index.html               # Visualizer dashboard UI
│   ├── server.py                # Visualizer backend server
│   └── style.css                # Visualizer styling
├── Cargo.lock                   # Deterministic dependency lockfile
├── Cargo.toml                   # Project dependencies and manifest
├── LICENSE                      # MIT License
└── README.md                    # Project documentation
```

---

## 📜 Academic & Research Context

Aegis directly addresses the core research question:
> *Can policy-aware compilation and explicit capability enforcement be integrated into a resource-bounded WebAssembly execution pipeline while maintaining correct behavior and acceptable compilation/runtime overhead?*

Our empirical evaluation establishes:
1. **Negligible Overhead:** Static analysis and capability checks add fewer than 30 ms to overall compilation latency.
2. **Deterministic Safety:** Unchecked ambient authority and denial-of-service loops are eliminated at the language and runtime boundary.
3. **Synergistic Optimization:** Security-aware IR optimizations reduce execution fuel consumption by over 40% without relaxing security guarantees.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
