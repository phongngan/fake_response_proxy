"""
Example python script for the 'script' response source.

The proxy invokes this as:
    python example_script.py [extra args...] <request_temp_file>

The script must:
  1. Read the raw HTTP request from the file passed as the LAST argument.
  2. Write a raw HTTP response to a NEW file.
  3. Print the absolute path of that response file to stdout (and only that).

The proxy reads the response file and then deletes both temp files.
"""
import sys
import os
import json
import tempfile
import time


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: example_script.py [args...] <request_file>", file=sys.stderr)
        return 2

    req_path = sys.argv[-1]
    with open(req_path, "r", encoding="utf-8", errors="replace") as f:
        raw_request = f.read()

    # ---- Build a response. Customize freely. ----
    payload = {
        "ok": True,
        "received_at": int(time.time()),
        "echoed_first_line": raw_request.splitlines()[0] if raw_request else "",
    }
    body = json.dumps(payload)
    response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
        f"{body}"
    )

    # Write response to a NEW temp file the proxy will read then delete.
    fd, out_path = tempfile.mkstemp(prefix="resp_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
        f.write(response)

    # Print ONLY the path on stdout.
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
