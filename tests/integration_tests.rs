use aegis::policy::AegisPolicy;
use aegis::runtime::{AegisRuntime, RuntimeError};
use aegis::security::FindingKind;
use aegis::{
    IrOptimizer, analyze_source, check_source, compile_source, execute_source, lower_to_ir,
};

#[test]
fn test_valid_program_compiles() {
    let src = r#"
        module test_valid;
        requires console.write;
        fn main() -> i32 {
            let x: i32 = 42;
            print_i32(x);
            return x;
        }
    "#;
    let wasm = compile_source(src, false).expect("Valid program should compile");
    assert!(!wasm.is_empty());
}

#[test]
fn test_invalid_syntax_rejected() {
    let src = r#"
        module bad_syntax
        fn main() { return; }
    "#;
    let res = check_source(src);
    assert!(res.is_err(), "Missing semicolon must be rejected");
}

#[test]
fn test_type_mismatch_rejected() {
    let src = r#"
        module bad_types;
        fn main() -> i32 {
            let x: i32 = true;
            return x;
        }
    "#;
    let res = check_source(src);
    assert!(res.is_err(), "Type mismatch must be rejected");
}

#[test]
fn test_immutable_reassignment_rejected() {
    let src = r#"
        module immutable_test;
        fn main() -> i32 {
            let x: i32 = 10;
            x = 20;
            return x;
        }
    "#;
    let res = check_source(src);
    assert!(
        res.is_err(),
        "Reassigning to immutable variable must be rejected"
    );
}

#[test]
fn test_missing_capability_rejected() {
    let src = r#"
        module missing_cap;
        // Does NOT declare 'requires console.write;'
        fn main() -> i32 {
            print_i32(100);
            return 0;
        }
    "#;
    let res = check_source(src);
    assert!(
        res.is_err(),
        "Calling privileged print_i32 without capability must be rejected"
    );
}

#[test]
fn test_authorized_console_output() {
    let src = r#"
        module authorized_run;
        requires console.write;
        fn main() -> i32 {
            let a: i32 = 15;
            let b: i32 = 25;
            print_i32(a + b);
            return 0;
        }
    "#;
    let policy = AegisPolicy::default();
    let res = execute_source(src, &policy).expect("Execution should succeed");
    assert_eq!(res.exit_code, 0);
    assert_eq!(res.output, vec!["40".to_string()]);
    assert!(res.error.is_none());
}

#[test]
fn test_unauthorized_capability_rejected() {
    let src = r#"
        module unauthorized_run;
        requires console.write;
        fn main() -> i32 {
            print_i32(100);
            return 0;
        }
    "#;
    let wasm = compile_source(src, false).unwrap();
    let mut policy = AegisPolicy::default();
    policy.capabilities.console_write = false; // Revoke

    let rt = AegisRuntime::new().unwrap();
    let res = rt.execute(&wasm, &policy);
    assert!(
        matches!(res.error, Some(RuntimeError::PolicyViolation { .. })),
        "Revoked capability must trigger PolicyViolation"
    );
    assert_eq!(
        res.fuel_consumed, 0,
        "No fuel consumed on pre-execution rejection"
    );
}

#[test]
fn test_fuel_exhaustion_terminates() {
    let src = r#"
        module infinite_loop;
        fn main() -> i32 {
            let mut x: i32 = 0;
            while true {
                x = x + 1;
            }
            return x;
        }
    "#;
    let mut policy = AegisPolicy::default();
    policy.resources.initial_fuel = 200; // tiny fuel budget

    let res = execute_source(src, &policy).expect("Should compile");
    assert_eq!(res.error, Some(RuntimeError::FuelExhausted));
    assert_eq!(res.fuel_remaining, 0);
}

#[test]
fn test_taint_vulnerability_detected() {
    let src = r#"
        module taint_vuln;
        requires console.write;
        requires host.read;
        fn main() -> i32 {
            let untrusted: i32 = read_i32();
            let derived: i32 = untrusted + 10;
            print_i32(derived);
            return 0;
        }
    "#;
    let report = analyze_source(src).expect("Source should check");
    assert_eq!(report.vulnerability_count(), 1);
    assert_eq!(report.findings[0].kind, FindingKind::Vulnerability);
}

#[test]
fn test_taint_sanitized_flow_allowed() {
    let src = r#"
        module taint_safe;
        requires console.write;
        requires host.read;
        fn main() -> i32 {
            let untrusted: i32 = read_i32();
            let sanitized: i32 = sanitize_i32(untrusted);
            print_i32(sanitized);
            return 0;
        }
    "#;
    let report = analyze_source(src).expect("Source should check");
    assert_eq!(report.vulnerability_count(), 0);
    assert_eq!(report.safe_flow_count(), 1);
    assert_eq!(report.findings[0].kind, FindingKind::SafeFlow);
}

#[test]
fn test_read_i32_without_capability_rejected_at_compile_time() {
    let src = r#"
        module read_unauth;
        fn main() -> i32 {
            let x: i32 = read_i32();
            return x;
        }
    "#;
    let err = compile_source(src, false).expect_err("Should fail compilation without host.read");
    assert!(
        err.message.contains("requires capability 'host.read'"),
        "Diagnostic must mention missing 'host.read' capability"
    );
}

#[test]
fn test_pure_compute_zero_imports_under_restrictive_policy() {
    let src = r#"
        module pure_compute;
        fn main() -> i32 {
            let a: i32 = 15;
            let b: i32 = 27;
            return a + b;
        }
    "#;
    let wasm = compile_source(src, false).expect("Pure compute must compile");

    // Inspect imports: must have ZERO imports
    let engine = wasmtime::Engine::default();
    let module = wasmtime::Module::new(&engine, &wasm).expect("Module must be valid wasm");
    assert_eq!(
        module.imports().len(),
        0,
        "Pure compute module must have 0 imports"
    );

    // Restrictive policy with ALL capabilities revoked
    let mut policy = AegisPolicy::default();
    policy.capabilities.console_write = false;
    policy.capabilities.host_read = false;

    let rt = AegisRuntime::new().unwrap();
    let res = rt.execute(&wasm, &policy);
    assert!(
        res.error.is_none(),
        "Pure compute must execute without capability errors"
    );
    assert_eq!(res.exit_code, 42);
}

#[test]
fn test_console_only_runs_with_host_read_disabled() {
    let src = r#"
        module console_only;
        requires console.write;
        fn main() -> i32 {
            print_i32(99);
            return 0;
        }
    "#;
    let wasm = compile_source(src, false).expect("Should compile");
    let engine = wasmtime::Engine::default();
    let module = wasmtime::Module::new(&engine, &wasm).expect("Module must be valid wasm");

    // Module should only import print_i32 (1 import), NOT read_i32!
    assert_eq!(module.imports().len(), 1);
    let import_names: Vec<String> = module.imports().map(|i| i.name().to_string()).collect();
    assert_eq!(import_names, vec!["print_i32"]);

    // Restrictive policy with host_read revoked
    let mut policy = AegisPolicy::default();
    policy.capabilities.console_write = true;
    policy.capabilities.host_read = false;

    let rt = AegisRuntime::new().unwrap();
    let res = rt.execute(&wasm, &policy);
    assert!(
        res.error.is_none(),
        "Console-only module must succeed even if host_read is false"
    );
    assert_eq!(res.output, vec!["99"]);
}

#[test]
fn test_read_i32_rejected_at_runtime_when_host_read_disabled() {
    let src = r#"
        module read_test;
        requires host.read;
        fn main() -> i32 {
            let x: i32 = read_i32();
            return x;
        }
    "#;
    let wasm = compile_source(src, false).expect("Should compile with declared capability");
    let mut policy = AegisPolicy::default();
    policy.capabilities.host_read = false; // Revoke host.read

    let rt = AegisRuntime::new().unwrap();
    let res = rt.execute(&wasm, &policy);
    assert!(
        matches!(res.error, Some(RuntimeError::PolicyViolation { ref capability, .. }) if capability == "host.read"),
        "Must trigger PolicyViolation for host.read"
    );
    assert_eq!(
        res.fuel_consumed, 0,
        "No fuel consumed on pre-execution rejection"
    );
}

#[test]
fn test_optimization_preserves_semantics() {
    let src = r#"
        module opt_test;
        requires console.write;
        fn main() -> i32 {
            let a: i32 = 10 * 5 + 2;
            let b: i32 = a + 0;
            let c: i32 = b * 1;
            print_i32(c);
            return c;
            print_i32(999);
        }
    "#;
    let policy = AegisPolicy::default();
    let wasm_unopt = compile_source(src, false).unwrap();
    let wasm_opt = compile_source(src, true).unwrap();

    let rt = AegisRuntime::new().unwrap();
    let res_unopt = rt.execute(&wasm_unopt, &policy);
    let res_opt = rt.execute(&wasm_opt, &policy);

    // Both must yield identical exit code and output
    assert_eq!(res_unopt.exit_code, 52);
    assert_eq!(res_opt.exit_code, 52);
    assert_eq!(res_unopt.output, vec!["52".to_string()]);
    assert_eq!(res_opt.output, vec!["52".to_string()]);

    // Optimized must consume less fuel
    assert!(
        res_opt.fuel_consumed < res_unopt.fuel_consumed,
        "Optimized program must consume less fuel than unoptimized"
    );
}

#[test]
fn test_malformed_wasm_rejected() {
    let garbage_bytes = vec![0x00, 0x61, 0x73, 0x6d, 0xff, 0xff, 0xff, 0xff];
    let policy = AegisPolicy::default();
    let rt = AegisRuntime::new().unwrap();
    let res = rt.execute(&garbage_bytes, &policy);
    assert!(matches!(res.error, Some(RuntimeError::MalformedBinary(_))));
}

#[test]
fn test_ir_optimizer_constant_folding_and_dce() {
    let src = r#"
        module ir_opt_test;
        fn main() -> i32 {
            let x: i32 = 20 + 30;
            let y: i32 = x * 1;
            if true {
                return y;
            } else {
                return 0;
            }
        }
    "#;
    let ir = lower_to_ir(src).expect("IR lowering should succeed");
    let mut opt = IrOptimizer::new();
    let optimized_ir = opt.optimize_program(&ir);

    // Verify constant folding occurred (20 + 30)
    assert!(opt.folding_count >= 1, "Constant folding must occur in IR");
    // Verify algebraic simplification occurred (y * 1 -> y)
    assert!(
        opt.simplification_count >= 1,
        "Algebraic simplification must occur in IR"
    );
    // Verify branch simplification and DCE occurred (branch on true -> jump, else block pruned)
    assert!(
        opt.dce_count >= 1,
        "Dead code elimination must prune unreachable blocks in IR"
    );

    // Verify optimized IR is valid
    aegis::ir::IrLowerer::verify_ir(&optimized_ir).expect("Optimized IR must pass verification");
}

#[test]
fn test_taint_branch_merge_detects_leak_if_one_branch_taints() {
    let src = r#"
        module taint_branch;
        requires console.write;
        requires host.read;
        fn main() -> i32 {
            let mut x: i32 = 0;
            if true {
                x = read_i32();
            } else {
                x = 10;
            }
            print_i32(x);
            return 0;
        }
    "#;
    let report = analyze_source(src).expect("Source should parse");
    assert_eq!(
        report.vulnerability_count(),
        1,
        "Must detect vulnerability when variable is tainted in one branch of if/else"
    );
}

#[test]
fn test_taint_loop_fixpoint_detects_carried_taint() {
    let src = r#"
        module taint_loop;
        requires console.write;
        requires host.read;
        fn main() -> i32 {
            let mut a: i32 = 0;
            let mut b: i32 = 0;
            while true {
                print_i32(a);
                a = b;
                b = read_i32();
            }
            return 0;
        }
    "#;
    let report = analyze_source(src).expect("Source should parse");
    assert_eq!(
        report.vulnerability_count(),
        1,
        "Must detect loop carried taint leak across iterations"
    );
}

#[test]
fn test_taint_scoped_variable_does_not_pollute_outer_clean_variable() {
    let src = r#"
        module taint_scope_safe;
        requires console.write;
        requires host.read;
        fn main() -> i32 {
            let x: i32 = 100;
            if true {
                let x: i32 = read_i32();
            }
            print_i32(x);
            return 0;
        }
    "#;
    let report = analyze_source(src).expect("Source should parse");
    assert_eq!(
        report.vulnerability_count(),
        0,
        "Inner shadowed variable must not taint outer variable (prevent false positive)"
    );
}

#[test]
fn test_taint_both_branches_sanitized_is_safe() {
    let src = r#"
        module taint_sanitized_branches;
        requires console.write;
        requires host.read;
        fn main() -> i32 {
            let mut val: i32 = read_i32();
            if true {
                val = sanitize_i32(val);
            } else {
                val = sanitize_i32(val);
            }
            print_i32(val);
            return 0;
        }
    "#;
    let report = analyze_source(src).expect("Source should parse");
    assert_eq!(
        report.vulnerability_count(),
        0,
        "Both branches sanitized must yield 0 vulnerabilities"
    );
    assert_eq!(
        report.safe_flow_count(),
        1,
        "Must recognize safe sanitized flow"
    );
}

#[test]
fn test_division_by_zero_traps_at_runtime() {
    let src = r#"
        module div_zero;
        fn main() -> i32 {
            let z: i32 = 0;
            return 100 / z;
        }
    "#;
    let rt = AegisRuntime::new().unwrap();
    let policy = AegisPolicy::default();

    // Unoptimized
    let wasm_unopt = compile_source(src, false).expect("Should compile");
    let res_unopt = rt.execute(&wasm_unopt, &policy);
    assert!(
        matches!(res_unopt.error, Some(RuntimeError::Trap(_))),
        "Division by zero must trap at runtime (unoptimized)"
    );

    // Optimized (optimizer must not fold away division by zero)
    let wasm_opt = compile_source(src, true).expect("Should compile");
    let res_opt = rt.execute(&wasm_opt, &policy);
    assert!(
        matches!(res_opt.error, Some(RuntimeError::Trap(_))),
        "Division by zero must trap at runtime (optimized)"
    );
}

#[test]
fn test_i32_min_divided_by_neg_one_traps_at_runtime() {
    let src = r#"
        module div_overflow;
        fn main() -> i32 {
            let min: i32 = -2147483648;
            let neg_one: i32 = -1;
            return min / neg_one;
        }
    "#;
    let rt = AegisRuntime::new().unwrap();
    let policy = AegisPolicy::default();

    // Unoptimized
    let wasm_unopt = compile_source(src, false).expect("Should compile");
    let res_unopt = rt.execute(&wasm_unopt, &policy);
    assert!(
        matches!(res_unopt.error, Some(RuntimeError::Trap(_))),
        "i32::MIN / -1 must trap at runtime (unoptimized)"
    );

    // Optimized (optimizer must not constant-fold away the trap)
    let wasm_opt = compile_source(src, true).expect("Should compile");
    let res_opt = rt.execute(&wasm_opt, &policy);
    assert!(
        matches!(res_opt.error, Some(RuntimeError::Trap(_))),
        "i32::MIN / -1 must trap at runtime (optimized)"
    );
}

#[test]
fn test_i32_overflow_wrapping_addition() {
    let src = r#"
        module overflow_add;
        fn main() -> i32 {
            let max: i32 = 2147483647;
            return max + 1;
        }
    "#;
    let rt = AegisRuntime::new().unwrap();
    let policy = AegisPolicy::default();

    let wasm_unopt = compile_source(src, false).expect("Should compile");
    let res_unopt = rt.execute(&wasm_unopt, &policy);
    assert!(res_unopt.error.is_none());
    assert_eq!(res_unopt.exit_code, -2147483648);

    let wasm_opt = compile_source(src, true).expect("Should compile");
    let res_opt = rt.execute(&wasm_opt, &policy);
    assert!(res_opt.error.is_none());
    assert_eq!(res_opt.exit_code, -2147483648);
}

#[test]
fn test_literal_range_validation() {
    // 3000000000 out of range
    let src_huge = r#"
        module huge_lit;
        fn main() -> i32 {
            return 3000000000;
        }
    "#;
    assert!(
        check_source(src_huge).is_err(),
        "Literal > 2^31 must be rejected"
    );

    // Positive 2147483648 out of range without minus sign
    let src_pos_overflow = r#"
        module pos_lit;
        fn main() -> i32 {
            return 2147483648;
        }
    "#;
    assert!(
        check_source(src_pos_overflow).is_err(),
        "Positive 2147483648 exceeds i32::MAX and must be rejected"
    );

    // -2147483648 is valid i32::MIN
    let src_min = r#"
        module min_lit;
        fn main() -> i32 {
            return -2147483648;
        }
    "#;
    let rt = AegisRuntime::new().unwrap();
    let policy = AegisPolicy::default();
    let wasm = compile_source(src_min, false).expect("Valid -2147483648 should compile");
    let res = rt.execute(&wasm, &policy);
    assert!(res.error.is_none());
    assert_eq!(res.exit_code, -2147483648);
}

#[test]
fn test_missing_return_paths_rejected() {
    let src_missing = r#"
        module missing_ret;
        fn main() -> i32 {
            let x: i32 = 10;
        }
    "#;
    assert!(
        check_source(src_missing).is_err(),
        "Function missing return statement must be rejected"
    );

    let src_partial = r#"
        module partial_ret;
        fn main() -> i32 {
            if true {
                return 1;
            }
        }
    "#;
    assert!(
        check_source(src_partial).is_err(),
        "Function with if-branch missing else return must be rejected"
    );

    let src_complete = r#"
        module complete_ret;
        fn main() -> i32 {
            if true {
                return 1;
            } else {
                return 2;
            }
        }
    "#;
    assert!(
        check_source(src_complete).is_ok(),
        "Function with exhaustive if-else return must be accepted"
    );
}
