import http.server, os, socketserver, sys
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
print(f"[mini-dev] serving {os.getcwd()} on http://127.0.0.1:1430", flush=True)
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args): sys.stderr.write("[mini-dev] " + (fmt % args) + "\n")
with socketserver.TCPServer(("127.0.0.1", 1430), H) as s:
    s.allow_reuse_address = True
    s.serve_forever()
