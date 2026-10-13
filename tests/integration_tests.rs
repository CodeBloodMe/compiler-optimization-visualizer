use aegis::policy::AegisPolicy;
use aegis::runtime::{AegisRuntime, RuntimeError};
use aegis::security::FindingKind;
use aegis::{analyze_source, check_source, compile_source, execute_source};

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
    assert_eq!(res.fuel_consumed, 0, "No fuel consumed on pre-execution rejection");
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
