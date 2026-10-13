import http.server
import socketserver
import json
import os
import shutil
import subprocess
import tempfile

HOST = os.environ.get("AEGIS_HOST", "127.0.0.1")
PORT = int(os.environ.get("AEGIS_PORT", "8080"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
MAX_PAYLOAD_BYTES = 1024 * 1024  # 1 MB
SUBPROCESS_TIMEOUT_SECS = 10

# Add LLVM/MinGW toolchain to PATH only if directory exists locally
LLVM_CANDIDATES = [
    os.environ.get("LLVM_BIN"),
    r"C:\Users\Admin\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260908-ucrt-x86_64\bin",
]
for p in LLVM_CANDIDATES:
    if p and os.path.isdir(p) and p not in os.environ.get("PATH", ""):
        os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")
        break

def find_aegis_binary() -> str:
    """Finds the aegis compiler executable dynamically without machine-specific assumptions."""
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

AEGIS_BIN = find_aegis_binary()
EXAMPLES_DIR = os.path.join(PROJECT_DIR, "examples")
BENCH_JSON = os.path.join(PROJECT_DIR, "benchmarks", "benchmark_results.json")

class AegisHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def do_GET(self):
        if self.path == "/api/examples":
            self.handle_get_examples()
        elif self.path == "/api/benchmarks":
            self.handle_get_benchmarks()
        else:
            super().do_GET()

    def do_POST(self):
        content_length_header = self.headers.get("Content-Length")
        if not content_length_header:
            self.send_error(411, "Length Required")
            return

        try:
            content_length = int(content_length_header)
        except ValueError:
            self.send_error(400, "Invalid Content-Length header")
            return

        if content_length > MAX_PAYLOAD_BYTES:
            self.send_error(413, f"Payload Too Large (limit: {MAX_PAYLOAD_BYTES} bytes)")
            return

        if content_length <= 0:
            self.send_error(400, "Empty payload")
            return

        post_data = self.rfile.read(content_length)
        try:
            req = json.loads(post_data.decode("utf-8"))
        except Exception:
            self.send_error(400, "Invalid JSON payload")
            return

        if not isinstance(req, dict):
            self.send_error(400, "JSON payload must be an object")
            return

        if self.path == "/api/check":
            self.handle_check(req)
        elif self.path == "/api/run":
            self.handle_run(req)
        elif self.path == "/api/analyze":
            self.handle_analyze(req)
        elif self.path == "/api/optimize":
            self.handle_optimize(req)
        else:
            self.send_error(404, "Endpoint not found")

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:" + str(PORT))
        self.end_headers()
        self.wfile.write(body)

    def validate_source(self, req):
        source = req.get("source")
        if not isinstance(source, str):
            self.send_json({"success": False, "error": "Field 'source' must be a string"}, status=400)
            return None
        if len(source) > MAX_PAYLOAD_BYTES:
            self.send_json({"success": False, "error": "Source code exceeds size limit"}, status=400)
            return None
        return source

    def handle_get_examples(self):
        examples = {}
        if os.path.exists(EXAMPLES_DIR):
            for fname in sorted(os.listdir(EXAMPLES_DIR)):
                if fname.endswith(".aegis"):
                    fpath = os.path.join(EXAMPLES_DIR, fname)
                    with open(fpath, "r", encoding="utf-8") as f:
                        examples[fname] = f.read()
        self.send_json(examples)

    def handle_get_benchmarks(self):
        if os.path.exists(BENCH_JSON):
            with open(BENCH_JSON, "r", encoding="utf-8") as f:
                self.send_json(json.load(f))
        else:
            self.send_json({})

    def handle_check(self, req):
        source = self.validate_source(req)
        if source is None:
            return

        with tempfile.NamedTemporaryFile("w", suffix=".aegis", delete=False, encoding="utf-8") as tmp:
            tmp.write(source)
            tmp_path = tmp.name

        try:
            res = subprocess.run(
                [AEGIS_BIN, "check", tmp_path],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SECS,
            )
            self.send_json({
                "success": res.returncode == 0,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "exit_code": res.returncode,
            })
        except subprocess.TimeoutExpired:
            self.send_json({
                "success": False,
                "error": f"Compilation check timed out after {SUBPROCESS_TIMEOUT_SECS} seconds",
                "exit_code": 124,
            }, status=504)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def handle_run(self, req):
        source = self.validate_source(req)
        if source is None:
            return

        fuel_raw = req.get("fuel", 1_000_000)
        if not isinstance(fuel_raw, int) or isinstance(fuel_raw, bool) or not (1 <= fuel_raw <= 100_000_000):
            self.send_json({"success": False, "error": "Field 'fuel' must be an integer between 1 and 100,000,000"}, status=400)
            return
        fuel = fuel_raw

        console_write_raw = req.get("console_write", True)
        if not isinstance(console_write_raw, bool):
            self.send_json({"success": False, "error": "Field 'console_write' must be a boolean"}, status=400)
            return
        console_write = console_write_raw

        host_read_raw = req.get("host_read", True)
        if not isinstance(host_read_raw, bool):
            self.send_json({"success": False, "error": "Field 'host_read' must be a boolean"}, status=400)
            return
        host_read = host_read_raw

        # Strict TOML construction using strictly validated boolean and integer types
        # preventing any arbitrary TOML configuration injection
        policy_toml = (
            "[capabilities]\n"
            f"console_write = {'true' if console_write else 'false'}\n"
            f"host_read = {'true' if host_read else 'false'}\n\n"
            "[resources]\n"
            f"initial_fuel = {fuel}\n"
            "max_memory_pages = 16\n\n"
            "[security]\n"
            "strict_imports = true\n"
            "deny_unknown_imports = true\n"
        )

        with tempfile.NamedTemporaryFile("w", suffix=".aegis", delete=False, encoding="utf-8") as src_tmp:
            src_tmp.write(source)
            src_path = src_tmp.name

        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8") as pol_tmp:
            pol_tmp.write(policy_toml)
            pol_path = pol_tmp.name

        try:
            res = subprocess.run(
                [AEGIS_BIN, "run", src_path, "--policy", pol_path],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SECS,
            )
            self.send_json({
                "success": res.returncode == 0,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "exit_code": res.returncode,
            })
        except subprocess.TimeoutExpired:
            self.send_json({
                "success": False,
                "error": f"Execution timed out after {SUBPROCESS_TIMEOUT_SECS} seconds",
                "exit_code": 124,
            }, status=504)
        finally:
            if os.path.exists(src_path):
                os.remove(src_path)
            if os.path.exists(pol_path):
                os.remove(pol_path)

    def handle_analyze(self, req):
        source = self.validate_source(req)
        if source is None:
            return

        with tempfile.NamedTemporaryFile("w", suffix=".aegis", delete=False, encoding="utf-8") as tmp:
            tmp.write(source)
            tmp_path = tmp.name

        try:
            res = subprocess.run(
                [AEGIS_BIN, "analyze", tmp_path],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SECS,
            )
            self.send_json({
                "success": res.returncode == 0,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "exit_code": res.returncode,
            })
        except subprocess.TimeoutExpired:
            self.send_json({
                "success": False,
                "error": f"Analysis timed out after {SUBPROCESS_TIMEOUT_SECS} seconds",
                "exit_code": 124,
            }, status=504)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def handle_optimize(self, req):
        source = self.validate_source(req)
        if source is None:
            return

        with tempfile.NamedTemporaryFile("w", suffix=".aegis", delete=False, encoding="utf-8") as src_tmp:
            src_tmp.write(source)
            src_path = src_tmp.name

        unopt_wasm = src_path + ".unopt.wasm"
        opt_wasm = src_path + ".opt.wasm"

        try:
            r1 = subprocess.run(
                [AEGIS_BIN, "compile", src_path, "-o", unopt_wasm],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SECS,
            )
            r2 = subprocess.run(
                [AEGIS_BIN, "compile", src_path, "-o", opt_wasm, "--opt"],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SECS,
            )

            if r1.returncode != 0 or r2.returncode != 0:
                self.send_json({"success": False, "error": r1.stderr + "\n" + r2.stderr})
                return

            unopt_size = os.path.getsize(unopt_wasm) if os.path.exists(unopt_wasm) else 0
            opt_size = os.path.getsize(opt_wasm) if os.path.exists(opt_wasm) else 0

            pol_path = os.path.join(PROJECT_DIR, "policies", "default.toml")
            run_unopt = subprocess.run(
                [AEGIS_BIN, "run", unopt_wasm, "--policy", pol_path],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SECS,
            )
            run_opt = subprocess.run(
                [AEGIS_BIN, "run", opt_wasm, "--policy", pol_path],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SECS,
            )

            self.send_json({
                "success": True,
                "unopt_size": unopt_size,
                "opt_size": opt_size,
                "run_unopt": run_unopt.stdout,
                "run_opt": run_opt.stdout,
            })
        except subprocess.TimeoutExpired:
            self.send_json({
                "success": False,
                "error": f"Optimization evaluation timed out after {SUBPROCESS_TIMEOUT_SECS} seconds",
                "exit_code": 124,
            }, status=504)
        finally:
            if os.path.exists(src_path):
                os.remove(src_path)
            if os.path.exists(unopt_wasm):
                os.remove(unopt_wasm)
            if os.path.exists(opt_wasm):
                os.remove(opt_wasm)

def run_server():
    server_address = (HOST, PORT)
    with socketserver.TCPServer(server_address, AegisHandler) as httpd:
        print(f"[Aegis Visualizer] Server bound exclusively to {HOST}:{PORT}")
        print(f"[Aegis Visualizer] Binary resolved to: {AEGIS_BIN}")
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()
