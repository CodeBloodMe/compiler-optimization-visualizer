import subprocess
import time
import json
import os
import shutil
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))

def find_aegis_binary() -> str:
    """Finds the aegis compiler executable dynamically across platforms."""
    env_bin = os.environ.get("AEGIS_BIN")
    if env_bin and os.path.isfile(env_bin):
        return env_bin

    which_bin = shutil.which("aegis") or shutil.which("aegis.exe")
    if which_bin and os.path.isfile(which_bin):
        return which_bin

    candidates = [
        os.path.join(PROJECT_DIR, "target", "x86_64-pc-windows-gnullvm", "debug", "aegis.exe"),
        os.path.join(PROJECT_DIR, "target", "x86_64-pc-windows-gnullvm", "release", "aegis.exe"),
        os.path.join(PROJECT_DIR, "target", "debug", "aegis.exe"),
        os.path.join(PROJECT_DIR, "target", "debug", "aegis"),
        os.path.join(PROJECT_DIR, "target", "release", "aegis.exe"),
        os.path.join(PROJECT_DIR, "target", "release", "aegis"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c

    return candidates[0]

# Add LLVM/MinGW toolchain to PATH only if directory exists locally
LLVM_CANDIDATES = [
    os.environ.get("LLVM_BIN"),
    r"C:\Users\Admin\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260908-ucrt-x86_64\bin",
]
for p in LLVM_CANDIDATES:
    if p and os.path.isdir(p) and p not in os.environ.get("PATH", ""):
        os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")
        break

AEGIS_BIN = find_aegis_binary()
EXAMPLES_DIR = os.path.join(PROJECT_DIR, "examples")
POLICIES_DIR = os.path.join(PROJECT_DIR, "policies")
BUILD_DIR = os.path.join(PROJECT_DIR, "build")
os.makedirs(BUILD_DIR, exist_ok=True)

def run_cmd(args, timeout=15):
    start = time.perf_counter()
    try:
        res = subprocess.run([AEGIS_BIN] + args, capture_output=True, text=True, timeout=timeout)
        duration_ms = (time.perf_counter() - start) * 1000.0
        return res.returncode, res.stdout, res.stderr, duration_ms
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s", (time.perf_counter() - start) * 1000.0

def main():
    print("================================================================")
    print("        AEGIS COMPILER EMPIRICAL BENCHMARK SUITE                ")
    print("================================================================")
    print(f"Target Binary: {AEGIS_BIN}")
    print(f"Platform:      {sys.platform}")
    print(f"Date:          {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("----------------------------------------------------------------\n")

    if not os.path.isfile(AEGIS_BIN):
        print(f"Error: Aegis binary not found at '{AEGIS_BIN}'. Build the project first.")
        sys.exit(1)

    results = {}

    # 1. Compilation Time Benchmark (10 iterations)
    print("1. [Benchmark] Compilation Latency (10 iterations):")
    hello_file = os.path.join(EXAMPLES_DIR, "hello.aegis")
    opt_file = os.path.join(EXAMPLES_DIR, "math_opt.aegis")
    out_hello = os.path.join(BUILD_DIR, "bench_hello.wasm")

    compile_times = []
    for i in range(10):
        code, out, err, dur = run_cmd(["compile", hello_file, "-o", out_hello])
        if code != 0:
            print(f"Compilation failed during benchmark iteration {i}: {err}")
            sys.exit(1)
        compile_times.append(dur)
    
    avg_compile_ms = sum(compile_times) / len(compile_times)
    print(f"   -> Average Compile Time (hello.aegis): {avg_compile_ms:.2f} ms")
    results["avg_compile_ms"] = round(avg_compile_ms, 2)

    # 2. Static Analysis Latency
    print("\n2. [Benchmark] Static Taint Analysis Latency (10 iterations):")
    taint_file = os.path.join(EXAMPLES_DIR, "taint_vulnerability.aegis")
    analysis_times = []
    for _ in range(10):
        code, out, err, dur = run_cmd(["analyze", taint_file])
        analysis_times.append(dur)
    
    avg_analysis_ms = sum(analysis_times) / len(analysis_times)
    print(f"   -> Average Static Analysis Time (taint_vulnerability.aegis): {avg_analysis_ms:.2f} ms")
    results["avg_analysis_ms"] = round(avg_analysis_ms, 2)

    # 3. Security Detection Rate and False Positives (Expanded labeled evaluation corpus)
    print("\n3. [Benchmark] Security Detection Accuracy (Expanded Corpus):")
    test_cases = [
        ("taint_vulnerability.aegis", True, "Direct untrusted input into sensitive sink"),
        ("branch_leak.aegis", True, "Branch-merged untrusted input into sensitive sink"),
        ("loop_carried_taint.aegis", True, "Loop-carried untrusted input into sensitive sink"),
        ("taint_sanitized.aegis", False, "Certified sanitizer before sensitive sink"),
        ("both_sanitized.aegis", False, "Exhaustively sanitized branches before sink"),
        ("scoped_shadow_clean.aegis", False, "Inner shadowed variable does not pollute outer variable"),
        ("hello.aegis", False, "Clean deterministic computation"),
        ("loop_fuel.aegis", False, "Clean iterative computation"),
    ]
    tp, fp, tn, fn = 0, 0, 0, 0
    corpus_details = []

    for file_name, should_be_vuln, desc in test_cases:
        p = os.path.join(EXAMPLES_DIR, file_name)
        code, out, err, _ = run_cmd(["analyze", p])
        detected_vuln = (code == 2)
        if should_be_vuln:
            if detected_vuln:
                tp += 1
                status = "TP (Detected expected vulnerability)"
            else:
                fn += 1
                status = "FN (Missed vulnerability)"
        else:
            if detected_vuln:
                fp += 1
                status = "FP (False positive alert)"
            else:
                tn += 1
                status = "TN (Clean program verified)"
        print(f"   - {file_name:<26} -> {status} [{desc}]")
        corpus_details.append({
            "file": file_name,
            "expected_vulnerable": should_be_vuln,
            "detected_vulnerable": detected_vuln,
            "status": status,
        })
    
    detection_rate = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 100.0
    fp_rate = (fp / (fp + tn)) * 100.0 if (fp + tn) > 0 else 0.0
    print(f"\n   -> True Positives:  {tp}, False Negatives: {fn}")
    print(f"   -> True Negatives:  {tn}, False Positives: {fp}")
    print(f"   -> Vulnerability Detection Rate: {detection_rate:.1f}%")
    print(f"   -> False Positive Rate:          {fp_rate:.1f}%")
    results["detection_rate_pct"] = round(detection_rate, 1)
    results["false_positive_pct"] = round(fp_rate, 1)
    results["corpus_size"] = len(test_cases)
    results["corpus_details"] = corpus_details

    # 4. Optimization Efficiency & Fuel Reduction
    print("\n4. [Benchmark] Security-Aware Optimization Impact:")
    unopt_wasm = os.path.join(BUILD_DIR, "bench_unopt.wasm")
    opt_wasm = os.path.join(BUILD_DIR, "bench_opt.wasm")

    c1, _, e1, _ = run_cmd(["compile", opt_file, "-o", unopt_wasm])
    c2, _, e2, _ = run_cmd(["compile", opt_file, "-o", opt_wasm, "--opt"])
    if c1 != 0 or c2 != 0:
        print(f"Error compiling math_opt.aegis: {e1} {e2}")
        sys.exit(1)

    unopt_size = os.path.getsize(unopt_wasm)
    opt_size = os.path.getsize(opt_wasm)
    size_reduction_pct = ((unopt_size - opt_size) / unopt_size) * 100.0

    default_policy = os.path.join(POLICIES_DIR, "default.toml")
    r1, out_unopt, err_unopt, _ = run_cmd(["run", unopt_wasm, "--policy", default_policy])
    r2, out_opt, err_opt, _ = run_cmd(["run", opt_wasm, "--policy", default_policy])
    if r1 != 0 or r2 != 0:
        print(f"Error executing optimized binaries: {err_unopt} {err_opt}")
        sys.exit(1)

    def parse_fuel(out):
        for line in out.splitlines():
            if "Fuel Consumed:" in line:
                return int(line.split(":")[1].replace("units", "").strip())
        return 0

    fuel_unopt = parse_fuel(out_unopt)
    fuel_opt = parse_fuel(out_opt)
    fuel_reduction_pct = ((fuel_unopt - fuel_opt) / fuel_unopt) * 100.0 if fuel_unopt > 0 else 0.0

    print(f"   -> Unoptimized Binary Size: {unopt_size} bytes, Fuel Consumed: {fuel_unopt} units")
    print(f"   -> Optimized Binary Size:   {opt_size} bytes, Fuel Consumed: {fuel_opt} units")
    print(f"   -> Code Size Reduction:     {size_reduction_pct:.1f}%")
    print(f"   -> Execution Fuel Reduction:{fuel_reduction_pct:.1f}%")
    results["size_reduction_pct"] = round(size_reduction_pct, 1)
    results["fuel_reduction_pct"] = round(fuel_reduction_pct, 1)

    # 5. Resource Limit Enforcement Determinism
    print("\n5. [Benchmark] Deterministic Resource Limit Enforcement:")
    loop_file = os.path.join(EXAMPLES_DIR, "loop_fuel.aegis")
    low_fuel_policy = os.path.join(POLICIES_DIR, "low_fuel.toml")
    code, out, err, _ = run_cmd(["run", loop_file, "--policy", low_fuel_policy])
    fuel_exhausted = (code == 3 or "Fuel exhausted" in err or "Fuel exhausted" in out)
    print(f"   -> Fuel limit termination observed: {fuel_exhausted} (Exit Code: {code})")
    results["resource_limit_enforced"] = fuel_exhausted

    # Save benchmark report
    report_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "benchmark_results.json"))
    with open(report_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[Aegis] Empirical benchmark report written to {report_file}")
    print("================================================================")

if __name__ == "__main__":
    main()
