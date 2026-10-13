import http.server
import socketserver
import json
import os
import subprocess
import tempfile

PORT = 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
AEGIS_BIN = os.path.join(PROJECT_DIR, "target", "x86_64-pc-windows-gnullvm", "debug", "aegis.exe")
LLVM_BIN = r"C:\Users\Admin\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260908-ucrt-x86_64\bin"

os.environ["PATH"] = LLVM_BIN + ";" + os.environ["PATH"]

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
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            req = json.loads(post_data.decode("utf-8"))
        except Exception:
            self.send_error(400, "Invalid JSON")
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
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def handle_get_examples(self):
        examples = {}
        if os.path.exists(EXAMPLES_DIR):
            for fname in os.listdir(EXAMPLES_DIR):
                if fname.endswith(".aegis"):
                    with open(os.path.join(EXAMPLES_DIR, fname), "r", encoding="utf-8") as f:
                        examples[fname] = f.read()
        self.send_json(examples)

    def handle_get_benchmarks(self):
        if os.path.exists(BENCH_JSON):
            with open(BENCH_JSON, "r", encoding="utf-8") as f:
                self.send_json(json.load(f))
        else:
            self.send_json({})

    def handle_check(self, req):
        source = req.get("source", "")
        with tempfile.NamedTemporaryFile("w", suffix=".aegis", delete=False, encoding="utf-8") as tmp:
            tmp.write(source)
            tmp_path = tmp.name

        try:
            res = subprocess.run([AEGIS_BIN, "check", tmp_path], capture_output=True, text=True)
            self.send_json({
                "success": res.returncode == 0,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "exit_code": res.returncode
            })
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def handle_run(self, req):
        source = req.get("source", "")
        fuel = req.get("fuel", 1000000)
        console_write = req.get("console_write", True)
        host_read = req.get("host_read", True)

        policy_toml = f"""[capabilities]
console_write = {str(console_write).lower()}
host_read = {str(host_read).lower()}

[resources]
initial_fuel = {fuel}
max_memory_pages = 16

[security]
strict_imports = true
deny_unknown_imports = true
"""
        with tempfile.NamedTemporaryFile("w", suffix=".aegis", delete=False, encoding="utf-8") as src_tmp:
            src_tmp.write(source)
            src_path = src_tmp.name

        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8") as pol_tmp:
            pol_tmp.write(policy_toml)
            pol_path = pol_tmp.name

        try:
            res = subprocess.run([AEGIS_BIN, "run", src_path, "--policy", pol_path], capture_output=True, text=True)
            self.send_json({
                "success": res.returncode == 0,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "exit_code": res.returncode
            })
        finally:
            if os.path.exists(src_path): os.remove(src_path)
            if os.path.exists(pol_path): os.remove(pol_path)

    def handle_analyze(self, req):
        source = req.get("source", "")
        with tempfile.NamedTemporaryFile("w", suffix=".aegis", delete=False, encoding="utf-8") as tmp:
            tmp.write(source)
            tmp_path = tmp.name

        try:
            res = subprocess.run([AEGIS_BIN, "analyze", tmp_path], capture_output=True, text=True)
            self.send_json({
                "success": res.returncode == 0,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "exit_code": res.returncode
            })
        finally:
            if os.path.exists(tmp_path): os.remove(tmp_path)

    def handle_optimize(self, req):
        source = req.get("source", "")
        with tempfile.NamedTemporaryFile("w", suffix=".aegis", delete=False, encoding="utf-8") as src_tmp:
            src_tmp.write(source)
            src_path = src_tmp.name

        unopt_wasm = src_path + ".unopt.wasm"
        opt_wasm = src_path + ".opt.wasm"

        try:
            r1 = subprocess.run([AEGIS_BIN, "compile", src_path, "-o", unopt_wasm], capture_output=True, text=True)
            r2 = subprocess.run([AEGIS_BIN, "compile", src_path, "-o", opt_wasm, "--opt"], capture_output=True, text=True)

            if r1.returncode != 0 or r2.returncode != 0:
                self.send_json({"success": False, "error": r1.stderr + "\n" + r2.stderr})
                return

            unopt_size = os.path.getsize(unopt_wasm) if os.path.exists(unopt_wasm) else 0
            opt_size = os.path.getsize(opt_wasm) if os.path.exists(opt_wasm) else 0

            # Run both
            pol_path = os.path.join(PROJECT_DIR, "policies", "default.toml")
            run_unopt = subprocess.run([AEGIS_BIN, "run", unopt_wasm, "--policy", pol_path], capture_output=True, text=True)
            run_opt = subprocess.run([AEGIS_BIN, "run", opt_wasm, "--policy", pol_path], capture_output=True, text=True)

            self.send_json({
                "success": True,
                "unopt_size": unopt_size,
                "opt_size": opt_size,
                "run_unopt": run_unopt.stdout,
                "run_opt": run_opt.stdout,
            })
        finally:
            if os.path.exists(src_path): os.remove(src_path)
            if os.path.exists(unopt_wasm): os.remove(unopt_wasm)
            if os.path.exists(opt_wasm): os.remove(opt_wasm)

def run_server():
    server_address = ("", PORT)
    with socketserver.TCPServer(server_address, AegisHandler) as httpd:
        print(f"[Aegis Visualizer] Server listening on http://localhost:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()
