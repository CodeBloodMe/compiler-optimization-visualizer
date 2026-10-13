use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use clap::{Parser, Subcommand};

use aegis::ir::IrLowerer;
use aegis::policy::AegisPolicy;
use aegis::runtime::{AegisRuntime, RuntimeError};
use aegis::{analyze_source, check_source, compile_source};

#[derive(Parser)]
#[command(name = "aegis")]
#[command(about = "Aegis: Security-First, Resource-Bounded WebAssembly Compiler", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse, type-check, and validate source semantics and capabilities
    Check {
        /// Source file path (.aegis)
        file: PathBuf,
    },

    /// Compile AegisLang source to WebAssembly binary (.wasm)
    Compile {
        /// Source file path (.aegis)
        file: PathBuf,

        /// Output path for generated WebAssembly binary
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Enable security-aware optimization passes
        #[arg(long)]
        opt: bool,
    },

    /// Inspect a WebAssembly binary imports, exports, and structure
    Inspect {
        /// WebAssembly file path (.wasm)
        file: PathBuf,
    },

    /// Execute a compiled WebAssembly binary or Aegis program under runtime policy & resource limits
    Run {
        /// WebAssembly binary (.wasm) or Aegis source (.aegis)
        file: PathBuf,

        /// Policy configuration file (.toml)
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Override initial execution fuel budget
        #[arg(long)]
        fuel: Option<u64>,
    },

    /// Perform static security and taint analysis on AegisLang source
    Analyze {
        /// Source file path (.aegis)
        file: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check { file } => handle_check(&file),
        Commands::Compile { file, output, opt } => handle_compile(&file, output, opt),
        Commands::Inspect { file } => handle_inspect(&file),
        Commands::Run {
            file,
            policy,
            fuel,
        } => handle_run(&file, policy.as_deref(), fuel),
        Commands::Analyze { file } => handle_analyze(&file),
    }
}

fn handle_check(path: &Path) -> ExitCode {
    let source = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading file '{:?}': {}", path, e);
            return ExitCode::from(1);
        }
    };

    println!("[aegis] Checking {:?}...", path);
    match check_source(&source) {
        Ok(prog) => {
            println!("[aegis] Syntax and semantic check passed successfully.");
            println!("  Module: {}", prog.module_name);
            println!(
                "  Declared capabilities: [{}]",
                prog.capabilities
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("  Defined functions: {}", prog.functions.len());

            // Check IR lowering
            match IrLowerer::lower_program(&prog) {
                Ok(ir) => {
                    println!("  Custom IR verified ({} functions).", ir.functions.len());
                }
                Err(d) => {
                    eprintln!("{}", d);
                    return ExitCode::from(1);
                }
            }

            ExitCode::SUCCESS
        }
        Err(diag) => {
            eprintln!("{}", diag);
            ExitCode::from(1)
        }
    }
}

fn handle_compile(path: &Path, output: Option<PathBuf>, opt: bool) -> ExitCode {
    let source = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading file '{:?}': {}", path, e);
            return ExitCode::from(1);
        }
    };

    let out_path = output.unwrap_or_else(|| {
        let mut p = path.to_path_buf();
        p.set_extension("wasm");
        p
    });

    println!(
        "[aegis] Compiling {:?} (opt={}) -> {:?}...",
        path, opt, out_path
    );

    match compile_source(&source, opt) {
        Ok(wasm_bytes) => {
            if let Some(parent) = out_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Err(e) = fs::write(&out_path, &wasm_bytes) {
                eprintln!("Error writing output binary '{:?}': {}", out_path, e);
                return ExitCode::from(1);
            }
            println!(
                "[aegis] Compilation succeeded: wrote {} bytes to {:?}",
                wasm_bytes.len(),
                out_path
            );
            ExitCode::SUCCESS
        }
        Err(diag) => {
            eprintln!("{}", diag);
            ExitCode::from(1)
        }
    }
}

fn handle_inspect(path: &Path) -> ExitCode {
    let wasm_bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading binary file '{:?}': {}", path, e);
            return ExitCode::from(1);
        }
    };

    println!("[aegis] Inspecting WebAssembly binary {:?} ({} bytes):", path, wasm_bytes.len());
    let engine = wasmtime::Engine::default();
    let module = match wasmtime::Module::new(&engine, &wasm_bytes) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("  Invalid WebAssembly binary: {}", e);
            return ExitCode::from(1);
        }
    };

    let mut import_count = 0;
    println!("  [Imports]:");
    for import in module.imports() {
        println!("    - {}.{} ({:?})", import.module(), import.name(), import.ty());
        import_count += 1;
    }

    let mut export_count = 0;
    println!("  [Exports]:");
    for export in module.exports() {
        println!("    - {} ({:?})", export.name(), export.ty());
        export_count += 1;
    }

    println!("  Summary: {} imports, {} exports", import_count, export_count);
    ExitCode::SUCCESS
}

fn handle_run(file: &Path, policy_path: Option<&Path>, fuel_override: Option<u64>) -> ExitCode {
    let mut policy = if let Some(p_path) = policy_path {
        match AegisPolicy::load_from_file(p_path) {
            Ok(pol) => pol,
            Err(e) => {
                eprintln!("Error loading policy file '{:?}': {}", p_path, e);
                return ExitCode::from(1);
            }
        }
    } else {
        AegisPolicy::default()
    };

    if let Some(f) = fuel_override {
        policy.resources.initial_fuel = f;
    }

    // Check if input is .wasm or .aegis
    let wasm_bytes = if file.extension().map_or(false, |ext| ext == "wasm") {
        match fs::read(file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Error reading wasm file '{:?}': {}", file, e);
                return ExitCode::from(1);
            }
        }
    } else {
        let src = match fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error reading source file '{:?}': {}", file, e);
                return ExitCode::from(1);
            }
        };
        match compile_source(&src, false) {
            Ok(b) => b,
            Err(diag) => {
                eprintln!("{}", diag);
                return ExitCode::from(1);
            }
        }
    };

    let runtime = match AegisRuntime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to initialize Wasmtime runtime: {}", e);
            return ExitCode::from(1);
        }
    };

    println!("[aegis] Executing with resource limits (initial fuel: {})...", policy.resources.initial_fuel);
    let result = runtime.execute(&wasm_bytes, &policy);

    for line in &result.output {
        println!("{}", line);
    }

    println!("--------------------------------------------------");
    println!("Execution Duration: {:?}", result.duration);
    println!("Fuel Consumed:      {} units", result.fuel_consumed);
    println!("Fuel Remaining:     {} units", result.fuel_remaining);
    println!("Exit Code:          {}", result.exit_code);

    if let Some(err) = &result.error {
        eprintln!("[Runtime Failure]: {}", err);
        match err {
            RuntimeError::PolicyViolation { .. } => ExitCode::from(2),
            RuntimeError::FuelExhausted => ExitCode::from(3),
            RuntimeError::MemoryLimitExceeded { .. } => ExitCode::from(4),
            RuntimeError::UnknownImport { .. } => ExitCode::from(5),
            RuntimeError::Trap(_) => ExitCode::from(6),
            RuntimeError::MalformedBinary(_) => ExitCode::from(7),
        }
    } else {
        ExitCode::SUCCESS
    }
}

fn handle_analyze(file: &Path) -> ExitCode {
    let source = match fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading file '{:?}': {}", file, e);
            return ExitCode::from(1);
        }
    };

    println!("[aegis] Performing static security & taint analysis on {:?}...", file);
    match analyze_source(&source) {
        Ok(report) => {
            println!("--------------------------------------------------");
            println!("Functions Analyzed:    {}", report.analyzed_functions);
            println!("Vulnerabilities Found: {}", report.vulnerability_count());
            println!("Safe Sanitized Flows:  {}", report.safe_flow_count());
            println!("--------------------------------------------------");

            for (idx, finding) in report.findings.iter().enumerate() {
                println!(
                    "[{}] {:?}: {}",
                    idx + 1,
                    finding.kind,
                    finding.description
                );
                println!("  Location: {}", finding.span);
                println!("  Trace path:");
                for step in &finding.flow_path {
                    println!("    -> {}", step);
                }
            }

            if report.has_vulnerabilities() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(diag) => {
            eprintln!("{}", diag);
            ExitCode::from(1)
        }
    }
}
