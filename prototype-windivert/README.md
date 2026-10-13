# windivert-redirect (prototype)

Standalone Rust prototype that proves out the **WinDivert-based redirect**
strategy for `fake_response_proxy`. It intercepts outbound TCP packets going
to a chosen port (default `443`) and rewrites them so they land on a local
proxy at `127.0.0.1:<listen-port>` — without ever binding the original port
and without needing a `hosts` entry.

## What "self-bootstrapping" means here

End-user double-clicks the .exe. The exe itself:

1. Checks whether it's elevated. If not, it re-launches via UAC and exits the
   unelevated parent.
2. Looks for `WinDivert.dll` + `WinDivert64.sys` in
   `%ProgramData%\FakeResponseProxy\windivert`.
3. If absent, downloads the pinned WinDivert release zip from GitHub,
   verifies the SHA-256 against a hash baked into the binary, and extracts
   the two needed files. The hash makes the download tamper-evident — if the
   bytes don't match what we shipped against, we refuse to install.
4. `LoadLibrary`s `WinDivert.dll`. The DLL then registers `WinDivert64.sys`
   as a kernel service automatically (the .sys is WHQL-signed by Microsoft,
   so no driver signing of your own is needed).
5. Opens the redirector filter and starts forwarding traffic.

There is nothing for the user to install, copy, or configure.

## Why `hosts` redirection wasn't enough

1. Source app uses a hard-coded IP instead of a hostname → `hosts` does nothing.
2. The target port (e.g. 443) is already bound by something else locally →
   the proxy can't bind it to receive traffic.

WinDivert sits at the kernel network layer, so neither limitation applies.

## Modes

| `--process` flag | Scope                                                  |
| ---------------- | ------------------------------------------------------ |
| omitted          | **All processes** — every outbound TCP to target_port. |
| `target.exe`     | Only the named process (matched case-insensitively).   |

Per-process mode opens a second WinDivert handle at the FLOW layer to learn
which local source ports belong to the target process, and the main NETWORK
rewriter consults that whitelist.

## Build

```powershell
cargo build --release
```

No external SDK, no `WinDivert.lib`, no `LIB` env setup. The DLL is loaded
at runtime, not link time.

## Run

```powershell
# All-process redirect of :443 -> 127.0.0.1:18443
.\target\release\windivert-redirect.exe --target-port 443 --listen-port 18443

# Only redirect traffic from "target.exe"
.\target\release\windivert-redirect.exe --process target.exe

# Verbose logs
$env:RUST_LOG="windivert_redirect=debug"; .\target\release\windivert-redirect.exe
```

Flags:

| Flag                  | Default                                            | Purpose                                   |
| --------------------- | -------------------------------------------------- | ----------------------------------------- |
| `--target-port`       | 443                                                | Outbound destination port to intercept    |
| `--listen-port`       | 18443                                              | Local proxy port on 127.0.0.1             |
| `--process`           | _(none)_                                           | Restrict to one image name                |
| `--windivert-dir`     | `%ProgramData%\FakeResponseProxy\windivert`        | Where to keep DLL+sys                     |
| `--no-uac`            | off                                                | Don't auto-elevate; fail fast if not root |
| env `FRP_SKIP_HASH=1` | _(unset)_                                          | Dev only — bypass SHA-256 check           |

Ctrl-C cleanly shuts down the driver handles.

## How to verify it works

1. Start a quick listener on the listen port:
   ```powershell
   python -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',18443)); s.listen(); c,a=s.accept(); print('got',a); print(c.recv(4096)); c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'); c.close()"
   ```
2. In another terminal, run the redirector. Accept the UAC prompt. First run
   will download WinDivert (~600 KiB) and log the install path.
3. In a third terminal, hit any external IP on port 443:
   ```powershell
   curl --insecure --resolve example.com:443:93.184.216.34 https://example.com/
   ```
   The Python listener should print the incoming connection (proving the
   forward redirect) and `curl` should receive a reply (proving the reverse
   path rewrites src back to the original IP:port so the app sees a normal
   answer).

## Updating the pinned WinDivert version

[bootstrap.rs](src/bootstrap.rs) has three constants near the top:

```rust
pub const WINDIVERT_VERSION: &str = "2.2.2";
pub const WINDIVERT_URL: &str = "...";
pub const WINDIVERT_ZIP_SHA256: &str = "...";
```

To bump:

1. Pick the release on GitHub.
2. Download the `-A.zip` artifact independently (e.g. browser).
3. `Get-FileHash WinDivert-X.Y.Z-A.zip -Algorithm SHA256`.
4. Paste the URL and the hash into the constants and rebuild.

Until the hash is filled in, run with `$env:FRP_SKIP_HASH="1"` during dev.

## Architecture notes

```
            ┌─────────────────────────────────────────┐
   app  ──► │ outbound TCP  ip.Dst != 127.0.0.1 :443  │
            └────────┬────────────────────────────────┘
                     ▼  WinDivertRecv (NETWORK layer)
         table.insert(src_port, {orig_src_ip, orig_dst_ip, orig_dst_port})
                     ▼  rewrite
                     src=127.0.0.1:src_port
                     dst=127.0.0.1:listen_port
                     addr.Loopback = 1, Outbound = 1
                     WinDivertHelperCalcChecksums
                     ▼  WinDivertSend  →  local proxy

            ┌─────────────────────────────────────────┐
proxy  ──►  │ loopback   src=127.0.0.1:listen_port    │
            └────────┬────────────────────────────────┘
                     ▼  WinDivertRecv
         state = table.get(dst_port)   (= original src_port)
                     ▼  rewrite
                     src=orig_dst_ip:orig_dst_port  (looks like server)
                     dst=orig_src_ip:dst_port       (back to app)
                     addr.Loopback = 0, Outbound = 0  (inbound)
                     WinDivertHelperCalcChecksums
                     ▼  WinDivertSend  →  app socket
```

## Caveats / scope of the prototype

- IPv4 only. Extend to IPv6 by adding `ip6 and tcp6` filter clauses and
  duplicating the 16-byte address rewrite.
- TCP only.
- Process-name match uses the last path component of
  `QueryFullProcessImageNameW` (case-insensitive). For tighter matching,
  compare the full path or use the PID directly.
- A pathological case: if some unrelated socket happens to pick the same
  ephemeral source port as the listen port (`18443`), the reverse filter
  would match it. Pick an obscure listen port to avoid collisions, or extend
  the filter to also constrain the loopback peer.
- Mapping table grows unbounded if FIN/RST is never seen. For production
  add an LRU + idle-timeout sweep.
- Download happens over HTTPS to github.com. If the user is offline at first
  launch, show a clear error and keep the saved hash so a later retry can
  succeed without rebuilding.

## Next step toward integration

When this prototype works against a sacrificial app, fold the modules into
`src-tauri/src/`:

- `src-tauri/src/divert/` — move `divert.rs` here.
- `src-tauri/src/bootstrap/` — move `bootstrap.rs` here; surface progress
  (downloading… verifying… installed) to the Tauri front-end via events.
- A rule shape like `{ match: host|cidr|port|process, action: redirect-to 127.0.0.1:<n> }`
  drives the filter expression. Enabling/disabling a rule opens/closes the
  WinDivert handle.
- Configure the Tauri Windows manifest to `requireAdministrator` so the
  whole app launches elevated; the explicit `relaunch_elevated()` here is
  only needed because this prototype is a plain console app.
