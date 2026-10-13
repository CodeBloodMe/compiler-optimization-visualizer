import subprocess
import time
import json
import os
import sys

AEGIS_BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "target", "x86_64-pc-windows-gnullvm", "debug", "aegis.exe"))
LLVM_BIN = r"C:\Users\Admin\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260908-ucrt-x86_64\bin"

os.environ["PATH"] = LLVM_BIN + ";" + os.environ["PATH"]

EXAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "examples"))
POLICIES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policies"))

def run_cmd(args):
    start = time.perf_counter()
    res = subprocess.run([AEGIS_BIN] + args, capture_output=True, text=True)
    duration_ms = (time.perf_counter() - start) * 1000.0
    return res.returncode, res.stdout, res.stderr, duration_ms

def main():
    print("================================================================")
    print("        AEGIS COMPILER EMPIRICAL BENCHMARK SUITE                ")
    print("================================================================")
    print(f"Target Binary: {AEGIS_BIN}")
    print(f"Platform:      Windows 64-bit (x86_64-pc-windows-gnullvm + UCRT)")
    print(f"Date:          {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("----------------------------------------------------------------\n")

    results = {}

    # 1. Compilation Time Benchmark (Repetitions: 10)
    print("1. [Benchmark] Compilation Latency (10 iterations):")
    hello_file = os.path.join(EXAMPLES_DIR, "hello.aegis")
    opt_file = os.path.join(EXAMPLES_DIR, "math_opt.aegis")

    compile_times = []
    for _ in range(10):
        code, out, err, dur = run_cmd(["compile", hello_file, "-o", "build/bench_hello.wasm"])
        assert code == 0
        compile_times.append(dur)
    
    avg_compile_ms = sum(compile_times) / len(compile_times)
    print(f"   -> Average Compile Time (hello.aegis): {avg_compile_ms:.2f} ms")
    results["avg_compile_ms"] = avg_compile_ms

    # 2. Static Analysis Latency
    print("\n2. [Benchmark] Static Taint Analysis Latency (10 iterations):")
    taint_file = os.path.join(EXAMPLES_DIR, "taint_vulnerability.aegis")
    analysis_times = []
    for _ in range(10):
        code, out, err, dur = run_cmd(["analyze", taint_file])
        analysis_times.append(dur)
    
    avg_analysis_ms = sum(analysis_times) / len(analysis_times)
    print(f"   -> Average Static Analysis Time (taint_vulnerability.aegis): {avg_analysis_ms:.2f} ms")
    results["avg_analysis_ms"] = avg_analysis_ms

    # 3. Security Detection Rate and False Positives
    print("\n3. [Benchmark] Security Detection Accuracy:")
    test_cases = [
        ("taint_vulnerability.aegis", True),   # True vulnerability
        ("taint_sanitized.aegis", False),      # Sanitized safe flow
        ("hello.aegis", False),                # Clean program
    ]
    tp, fp, tn, fn = 0, 0, 0, 0
    for file_name, should_be_vuln in test_cases:
        p = os.path.join(EXAMPLES_DIR, file_name)
        code, out, err, _ = run_cmd(["analyze", p])
        detected_vuln = (code == 2)
        if should_be_vuln:
            if detected_vuln:
                tp += 1
            else:
                fn += 1
        else:
            if detected_vuln:
                fp += 1
            else:
                tn += 1
    
    detection_rate = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 100.0
    fp_rate = (fp / (fp + tn)) * 100.0 if (fp + tn) > 0 else 0.0
    print(f"   -> True Positives:  {tp}, False Negatives: {fn}")
    print(f"   -> True Negatives:  {tn}, False Positives: {fp}")
    print(f"   -> Vulnerability Detection Rate: {detection_rate:.1f}%")
    print(f"   -> False Positive Rate:          {fp_rate:.1f}%")
    results["detection_rate_pct"] = detection_rate
    results["false_positive_pct"] = fp_rate

    # 4. Optimization Efficiency & Fuel Reduction
    print("\n4. [Benchmark] Security-Aware Optimization Impact:")
    run_cmd(["compile", opt_file, "-o", "build/bench_unopt.wasm"])
    run_cmd(["compile", opt_file, "-o", "build/bench_opt.wasm", "--opt"])
    unopt_size = os.path.getsize("build/bench_unopt.wasm")
    opt_size = os.path.getsize("build/bench_opt.wasm")
    size_reduction_pct = ((unopt_size - opt_size) / unopt_size) * 100.0

    _, out_unopt, _, _ = run_cmd(["run", "build/bench_unopt.wasm", "--policy", os.path.join(POLICIES_DIR, "default.toml")])
    _, out_opt, _, _ = run_cmd(["run", "build/bench_opt.wasm", "--policy", os.path.join(POLICIES_DIR, "default.toml")])

    def parse_fuel(out):
        for line in out.splitlines():
            if "Fuel Consumed:" in line:
                return int(line.split(":")[1].replace("units", "").strip())
        return 0

    fuel_unopt = parse_fuel(out_unopt)
    fuel_opt = parse_fuel(out_opt)
    fuel_reduction_pct = ((fuel_unopt - fuel_opt) / fuel_unopt) * 100.0

    print(f"   -> Unoptimized Binary Size: {unopt_size} bytes, Fuel Consumed: {fuel_unopt} units")
    print(f"   -> Optimized Binary Size:   {opt_size} bytes, Fuel Consumed: {fuel_opt} units")
    print(f"   -> Code Size Reduction:     {size_reduction_pct:.1f}%")
    print(f"   -> Execution Fuel Reduction:{fuel_reduction_pct:.1f}%")
    results["size_reduction_pct"] = size_reduction_pct
    results["fuel_reduction_pct"] = fuel_reduction_pct

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
