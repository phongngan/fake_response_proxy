"""Tiny dev server. Tauri runs this from src-tauri/, we chdir to ../src."""
import http.server
import os
import socketserver
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "src")
os.chdir(ROOT)
print(f"dev-server: serving {os.getcwd()} on http://127.0.0.1:1420", flush=True)

class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[dev-server] " + (fmt % args) + "\n")

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

with socketserver.TCPServer(("127.0.0.1", 1420), Handler) as httpd:
    httpd.allow_reuse_address = True
    httpd.serve_forever()
