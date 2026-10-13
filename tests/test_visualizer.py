import unittest
import threading
import time
import urllib.request
import urllib.error
import json
import os
import sys

# Import server
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "visualizer")))
import server

class VisualizerSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.PORT = 8999
        server.HOST = "127.0.0.1"
        cls.httpd = server.socketserver.TCPServer((server.HOST, server.PORT), server.AegisHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def post(self, endpoint, data):
        url = f"http://127.0.0.1:{server.PORT}{endpoint}"
        body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
            method="POST",
        )
        return urllib.request.urlopen(req)

    def test_localhost_only_binding(self):
        self.assertEqual(server.HOST, "127.0.0.1")

    def test_examples_endpoint(self):
        url = f"http://127.0.0.1:{server.PORT}/api/examples"
        res = urllib.request.urlopen(url)
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode())
        self.assertIn("hello.aegis", data)

    def test_valid_check_request(self):
        src = "module check_test;\nfn main() -> i32 { return 0; }"
        res = self.post("/api/check", {"source": src})
        self.assertEqual(res.status, 200)
        resp_data = json.loads(res.read().decode())
        self.assertTrue(resp_data["success"])

    def test_invalid_fuel_rejected(self):
        # Attempt non-integer / string injection
        src = "module fuel_test;\nfn main() -> i32 { return 0; }"
        payload = {"source": src, "fuel": "malicious\n[evil]\nattack=true"}
        try:
            self.post("/api/run", payload)
            self.fail("Expected 400 for invalid fuel")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

    def test_boolean_type_enforcement_for_capabilities(self):
        # Attempt string injection in capability boolean
        src = "module cap_test;\nfn main() -> i32 { return 0; }"
        payload = {"source": src, "console_write": "true\n[injected]"}
        try:
            self.post("/api/run", payload)
            self.fail("Expected 400 for string console_write")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

    def test_missing_source_rejected(self):
        payload = {"not_source": 123}
        try:
            self.post("/api/check", payload)
            self.fail("Expected 400 for missing source")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

if __name__ == "__main__":
    unittest.main()
