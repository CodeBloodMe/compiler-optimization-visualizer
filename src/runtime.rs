use anyhow::Result;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use wasmtime::*;

use crate::policy::AegisPolicy;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    #[error("Policy violation: capability '{capability}' denied by runtime policy: {details}")]
    PolicyViolation { capability: String, details: String },

    #[error("Unknown import rejected: module '{module}', name '{name}' is not authorized")]
    UnknownImport { module: String, name: String },

    #[error("Fuel exhausted: program exceeded the configured execution fuel budget")]
    FuelExhausted,

    #[error(
        "Linear memory limit exceeded: requested memory exceeds maximum allowed ({max_pages} pages)"
    )]
    MemoryLimitExceeded { max_pages: u32 },

    #[error("WebAssembly runtime trap: {0}")]
    Trap(String),

    #[error("Malformed WebAssembly binary: {0}")]
    MalformedBinary(String),
}

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub output: Vec<String>,
    pub fuel_consumed: u64,
    pub fuel_remaining: u64,
    pub duration: Duration,
    pub error: Option<RuntimeError>,
}

struct HostState {
    #[allow(dead_code)]
    output: Arc<Mutex<Vec<String>>>,
    limits: StoreLimits,
}

pub struct AegisRuntime {
    engine: Engine,
}

impl AegisRuntime {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.cranelift_opt_level(OptLevel::Speed);
        let engine = Engine::new(&config)?;
        Ok(Self { engine })
    }

    pub fn execute(&self, wasm_bytes: &[u8], policy: &AegisPolicy) -> ExecutionResult {
        let start_time = Instant::now();
        let output_log = Arc::new(Mutex::new(Vec::new()));

        // 1. Validate binary structure
        let module = match Module::new(&self.engine, wasm_bytes) {
            Ok(m) => m,
            Err(e) => {
                return ExecutionResult {
                    exit_code: 1,
                    output: Vec::new(),
                    fuel_consumed: 0,
                    fuel_remaining: policy.resources.initial_fuel,
                    duration: start_time.elapsed(),
                    error: Some(RuntimeError::MalformedBinary(e.to_string())),
                };
            }
        };

        // 2. Pre-execution capability & import authorization check
        for import in module.imports() {
            let mod_name = import.module();
            let field_name = import.name();

            if mod_name == "aegis_host" {
                match field_name {
                    "print_i32" | "print_bool" => {
                        if !policy.is_capability_granted("console.write") {
                            return ExecutionResult {
                                exit_code: 2,
                                output: Vec::new(),
                                fuel_consumed: 0,
                                fuel_remaining: policy.resources.initial_fuel,
                                duration: start_time.elapsed(),
                                error: Some(RuntimeError::PolicyViolation {
                                    capability: "console.write".to_string(),
                                    details: "Module requires 'console.write' but the runtime policy does not authorize it"
                                        .to_string(),
                                }),
                            };
                        }
                    }
                    "read_i32" => {
                        if !policy.is_capability_granted("host.read") {
                            return ExecutionResult {
                                exit_code: 2,
                                output: Vec::new(),
                                fuel_consumed: 0,
                                fuel_remaining: policy.resources.initial_fuel,
                                duration: start_time.elapsed(),
                                error: Some(RuntimeError::PolicyViolation {
                                    capability: "host.read".to_string(),
                                    details: "Module requires 'host.read' but the runtime policy does not authorize it"
                                        .to_string(),
                                }),
                            };
                        }
                    }
                    "sanitize_i32" => {}
                    _ => {
                        if policy.security.deny_unknown_imports {
                            return ExecutionResult {
                                exit_code: 2,
                                output: Vec::new(),
                                fuel_consumed: 0,
                                fuel_remaining: policy.resources.initial_fuel,
                                duration: start_time.elapsed(),
                                error: Some(RuntimeError::UnknownImport {
                                    module: mod_name.to_string(),
                                    name: field_name.to_string(),
                                }),
                            };
                        }
                    }
                }
            } else if policy.security.deny_unknown_imports {
                return ExecutionResult {
                    exit_code: 2,
                    output: Vec::new(),
                    fuel_consumed: 0,
                    fuel_remaining: policy.resources.initial_fuel,
                    duration: start_time.elapsed(),
                    error: Some(RuntimeError::UnknownImport {
                        module: mod_name.to_string(),
                        name: field_name.to_string(),
                    }),
                };
            }
        }

        // 3. Configure store with linear-memory limits
        let limits = StoreLimitsBuilder::new()
            .memory_size(policy.resources.max_memory_pages as usize * 65536)
            .build();

        let state = HostState {
            output: Arc::clone(&output_log),
            limits,
        };

        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);

        // 4. Set initial fuel
        if let Err(e) = store.set_fuel(policy.resources.initial_fuel) {
            return ExecutionResult {
                exit_code: 1,
                output: Vec::new(),
                fuel_consumed: 0,
                fuel_remaining: policy.resources.initial_fuel,
                duration: start_time.elapsed(),
                error: Some(RuntimeError::Trap(e.to_string())),
            };
        }

        // 5. Build linker and bind authorized host functions
        let mut linker = Linker::new(&self.engine);

        // Bind print_i32
        if policy.is_capability_granted("console.write") {
            let out_clone = Arc::clone(&output_log);
            let _ = linker.func_wrap("aegis_host", "print_i32", move |val: i32| {
                let mut out = out_clone.lock().unwrap();
                out.push(format!("{}", val));
            });

            let out_clone_b = Arc::clone(&output_log);
            let _ = linker.func_wrap("aegis_host", "print_bool", move |val: i32| {
                let mut out = out_clone_b.lock().unwrap();
                out.push(format!("{}", val != 0));
            });
        }

        // Bind read_i32: Explicitly labeled mocked runtime input fixture
        if policy.is_capability_granted("host.read") {
            let _ = linker.func_wrap("aegis_host", "read_i32", || -> i32 {
                // [MOCKED RUNTIME INPUT]: Deterministic host test fixture (42) for reproducible evaluation
                42
            });
        }

        // Bind sanitize_i32
        let _ = linker.func_wrap("aegis_host", "sanitize_i32", |val: i32| -> i32 {
            val.clamp(0, 1000)
        });

        // 6. Instantiate module
        let instance = match linker.instantiate(&mut store, &module) {
            Ok(inst) => inst,
            Err(err) => {
                let err_str = err.to_string();
                let runtime_err = if err_str.contains("unknown import") {
                    RuntimeError::UnknownImport {
                        module: "unknown".to_string(),
                        name: "unknown".to_string(),
                    }
                } else {
                    RuntimeError::Trap(err_str)
                };
                return ExecutionResult {
                    exit_code: 1,
                    output: output_log.lock().unwrap().clone(),
                    fuel_consumed: 0,
                    fuel_remaining: store.get_fuel().unwrap_or(0),
                    duration: start_time.elapsed(),
                    error: Some(runtime_err),
                };
            }
        };

        // 7. Invoke main function
        let main_func = instance.get_func(&mut store, "main");
        let (exit_code, runtime_err) = match main_func {
            Some(func) => {
                let mut results = [Val::I32(0)];
                match func.call(&mut store, &[], &mut results) {
                    Ok(_) => {
                        let code = results[0].i32().unwrap_or(0);
                        (code, None)
                    }
                    Err(trap) => {
                        let trap_str = trap.to_string();
                        let current_fuel = store.get_fuel().unwrap_or(1);
                        if current_fuel == 0
                            || trap_str.contains("fuel")
                            || trap_str.contains("exhausted")
                        {
                            (-1, Some(RuntimeError::FuelExhausted))
                        } else if trap_str.contains("memory") || trap_str.contains("out of bounds")
                        {
                            (
                                -2,
                                Some(RuntimeError::MemoryLimitExceeded {
                                    max_pages: policy.resources.max_memory_pages,
                                }),
                            )
                        } else {
                            (-3, Some(RuntimeError::Trap(trap_str)))
                        }
                    }
                }
            }
            None => (0, None),
        };

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = policy.resources.initial_fuel.saturating_sub(fuel_remaining);
        let duration = start_time.elapsed();
        let output = output_log.lock().unwrap().clone();

        ExecutionResult {
            exit_code,
            output,
            fuel_consumed,
            fuel_remaining,
            duration,
            error: runtime_err,
        }
    }
}
