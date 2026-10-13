# Fake Response Proxy

Phần mềm proxy HTTP/HTTPS chạy local trên Windows, dùng để **chặn và fake response** cho các domain mà phần mềm mã nguồn đóng ngầm gọi tới.

Bối cảnh: nhiều phần mềm Windows ngầm kết nối tới các trang HTTP/HTTPS bên ngoài để thu thập dữ liệu. Bạn vẫn cần dùng phần mềm đó, nhưng muốn chặn các kết nối ngầm đó và trả về response giả để phần mềm vẫn hoạt động bình thường.

App được viết bằng **Tauri 2 (Rust)** cho phần backend + **vanilla HTML/CSS/JS** cho UI. Output là `.msi` và `.exe (NSIS)` installer.

---

## Tính năng

### 1. Multi-listener proxy
- Cấu hình **nhiều listener cùng lúc**: mỗi listener là bộ `(scheme, bind IP, port)`.
- Hỗ trợ song song HTTP và HTTPS, nhiều IP loopback (`127.0.0.1`, `127.0.0.2`, ...), nhiều port (`80`, `443`, `8080`, `8443`, …).
- Mỗi listener có status riêng: `running` / `stopped` / `failed` + thông báo lỗi cụ thể nếu bind thất bại (permission denied, address in use…).

### 2. Rule-based response
Mỗi rule khớp request theo:
- **Listener ID** (rule chỉ áp dụng cho listener cụ thể, hoặc tất cả)
- **Host** (exact, case-insensitive, hoặc bỏ trống = match tất cả)
- **Method** (`GET`/`POST`/…, hoặc bỏ trống = match tất cả)
- **Path regex** (regex khớp `path?query`)

Rule đầu tiên enabled khớp được sẽ thắng. Có 3 cách sinh response:

| Loại | Mô tả |
|------|-------|
| **Raw text** | Paste raw HTTP response đầy đủ vào textarea trong app. |
| **File** | Đường dẫn tới file chứa raw HTTP response. App đọc file mỗi lần request đến. |
| **Python script** | App ghi raw request ra file tạm → chạy `python <script.py> [args...] <req_tempfile>` → script in ra stdout đường dẫn file response. App đọc file đó để phản hồi, sau đó xoá cả file request và response tạm. |

### 3. HTTPS — tự sinh & cài CA
- Lần đầu chạy, app tự sinh **root CA** RSA-2048 (`Fake Response Proxy Root CA`) tại `%APPDATA%\FakeResponseProxy\ca\`.
- Sinh **leaf cert per-SNI** on-the-fly (rcgen + rustls). Cache theo SNI để tránh sinh lại.
- Fallback khi client không gửi SNI (vd: `curl https://127.0.0.1`): sinh cert SAN gồm `localhost` + `127.0.0.1` + `::1`.
- Cài CA bằng 1 click: `LocalMachine\Root` (cần admin) hoặc `CurrentUser\Root` (không cần admin). Có thể uninstall.
- Tự detect CA đã cài hay chưa qua thumbprint SHA-1.

### 4. WinDivert redirect (nâng cao)
Thay vì chỉ dựa vào file `hosts`, app có thể **chặn TCP outbound ở tầng network** bằng [WinDivert](https://github.com/basil00/WinDivert) — redirect bất kỳ kết nối nào (theo IP, port, hoặc process name) về proxy local.

- Tự **tải WinDivert 2.2.2** từ GitHub (~600 KiB), verify SHA-256, lưu vào `%ProgramData%\FakeResponseProxy\windivert\`.
- Driver `WinDivert64.sys` tự cài vào kernel lần đầu (cần admin).
- Mỗi redirect rule lọc theo:
  - **Target port** (vd: 443 = mọi HTTPS outbound)
  - **Listen port** (vd: 8443 = proxy của ta)
  - **Process name** (optional, vd: `target-app.exe` — chỉ chặn 1 app cụ thể)
  - **Target IP/hostname** (optional, comma-separated; hostname được resolve về IP khi start rule)
  - **Redirect IP** (mặc định `127.0.0.1`, có thể trỏ tới máy khác — xem lưu ý phía dưới)
- ⚠️ **Khuyến nghị**: thay vì `127.0.0.1`, hãy dùng **IP LAN thật** của máy (xem `ipconfig`, vd `10.x.y.z`) và bind listener vào `0.0.0.0:<port>`. Redirect về `127.0.0.1` có thể bị Windows TCP stack drop silently do anti-spoofing trên loopback.
- Không cần sửa `hosts`, không cần app đích biết về proxy.
- App tự offer "Restart as Administrator" qua UAC nếu user chưa elevated.

### 5. History
SQLite ring buffer tại `%APPDATA%\FakeResponseProxy\history.sqlite`:
- **1000 request gần nhất** (metadata: time, listener, scheme, method, host, path, status, rule, duration).
- **100 request đầy đủ** (raw request + raw response body) — click vào dòng trong tab History để xem full message.

### 6. Tích hợp Windows
- **Tray icon** với menu: Show / Start proxy / Stop proxy / Quit.
- **Auto-start với Windows** (tuỳ chọn) qua `tauri-plugin-autostart`.
- **Auto-start listener khi app launch** (tuỳ chọn trong Settings).
- Đóng cửa sổ ⇒ hide-to-tray (không thực sự thoát).

---

## Yêu cầu hệ thống

- **Windows 10/11 64-bit**
- **Microsoft Edge WebView2 Runtime** (Windows 11 có sẵn; Windows 10: [tải tại đây](https://developer.microsoft.com/microsoft-edge/webview2/))
- **Python 3.7+** (chỉ cần nếu dùng response option "Python script")

> ⚠️ Nếu WebView2 bị stuck (ứng dụng mở ra cửa sổ trắng không có nội dung), **restart Windows** để clear state. Đây là lỗi thỉnh thoảng gặp của WebView2 runtime, không liên quan đến code app.

---

## Cài đặt cho người dùng cuối

Có 2 dạng installer:

| File | Kích thước | Cách dùng |
|------|-----------|-----------|
| `Fake Response Proxy_0.1.0_x64_en-US.msi` | ~3.6 MB | Right-click → Install. Hoặc silent: `msiexec /i "Fake Response Proxy_0.1.0_x64_en-US.msi" /qn` |
| `Fake Response Proxy_0.1.0_x64-setup.exe` | ~2.7 MB | Double-click. NSIS wizard hướng dẫn. |

Sau khi cài, mở app từ Start Menu.

### Khi cần chạy as Administrator
- Bind port `<1024` (vd: 80, 443).
- Cài CA vào `LocalMachine\Root` (system-wide trust).
- Bật **redirect rule** (WinDivert cần admin để tải driver kernel).

Right-click shortcut → Run as administrator. Hoặc trong app, vào tab **Redirect** click nút "Restart as Administrator" → UAC prompt.

---

## Hướng dẫn sử dụng

### Tab Server
Hiển thị danh sách listener với status realtime. Nút **Start all enabled** / **Stop all** / **Refresh**. Mỗi listener có nút Start/Stop riêng.

Nếu listener fail (vd: port 443 không có admin), badge "failed" + dòng error đỏ chỉ rõ lý do.

### Tab Rules
CRUD các response rule. Mỗi rule có:
- **Name**, **Enabled** checkbox
- **Listener ID** (bỏ trống = tất cả listener)
- **Host** / **Method** / **Path regex**
- **Response source**: chọn 1 trong 3 (raw text / file / script)

Rule được lưu vào `%APPDATA%\FakeResponseProxy\rules.json`.

### Tab History
Bảng request log (mới nhất ở trên). Click vào dòng có badge "full" để xem raw request + raw response.

Nút **Clear all** xoá toàn bộ lịch sử.

### Tab Certificate
- Hiển thị thumbprint CA + trạng thái cài đặt (user / system).
- **Install (current user)**: không cần admin, chỉ user này trust CA.
- **Install (system, requires admin)**: cần app chạy elevated, mọi user và mọi process trên máy đều trust.
- **Copy PEM to clipboard**: lấy nội dung CA để cài thủ công vào browser / java keystore / mobile device.

### Tab Settings
**Listeners**: bảng CRUD listener. Thêm/xoá/sửa từng dòng:

| ID | Scheme | Bind IP | Port |
|----|--------|---------|------|
| `http-8080` | http | 127.0.0.1 | 8080 |
| `https-8443` | https | 127.0.0.1 | 8443 |
| `http-80-alt` | http | 127.0.0.2 | 80 |

ID phải unique. Sau khi Save, quay lại tab Server để Start.

**Other settings**:
- Python interpreter path (mặc định `python` trong PATH)
- Auto-start enabled listeners on app launch

**Autostart with Windows**: enable/disable launch khi đăng nhập.

### Tab Redirect (WinDivert)
Cho phép bắt outbound TCP của 1 app cụ thể về proxy local mà không cần sửa `hosts`.

**Quy trình điển hình:**
1. Click **Install WinDivert** (download driver, cần admin).
2. **+ New redirect rule** với:
   - `target_port` = 443 (HTTPS) hoặc 80
   - `listen_port` = port của HTTPS listener trong tab Settings (vd 8443)
   - `process` = `target-app.exe` (optional — chỉ chặn process này, nếu bỏ trống chặn mọi process)
   - `target` = `api.bad-vendor.com, 1.2.3.4` (optional — chỉ chặn destination này)
3. Save → Start rule.

Outbound packet matching rule sẽ được rewrite destination → proxy local. Reply path tự khôi phục IP gốc cho app (app không biết bị MITM).

---

## Build từ source (cho developer)

### Yêu cầu

1. **Rust toolchain** (MSVC):
   ```powershell
   winget install Rustlang.Rustup
   rustup default stable-msvc
   ```
2. **Visual Studio Build Tools 2022** với workload "Desktop development with C++":
   ```powershell
   winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--quiet --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.Windows10SDK"
   ```
3. **Node.js 18+** ([nodejs.org](https://nodejs.org/))
4. **Python 3.7+** cho dev server (tuỳ chọn, đã có trong PATH)

### Lần đầu setup

```powershell
cd c:\path\to\fake_response_proxy
npm install
pwsh -File scripts/gen-icons.ps1   # sinh app icon từ source 512x512 (placeholder "FR")
```

### Chế độ dev

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
npm run dev
```

Tauri sẽ:
- Chạy `python src-tauri/dev-server.py` để serve frontend tại `http://127.0.0.1:1420`.
- Compile + chạy debug binary.
- Auto-rebuild Rust khi sửa file trong `src-tauri/`.
- Auto-open DevTools (chỉ trong debug build).

Sửa file frontend (`src/*.html`, `*.css`, `*.js`) → bấm `Ctrl+R` trong cửa sổ app để reload.

### Build production installers

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
npm run build
```

Output trong `src-tauri/target/release/bundle/`:
- `msi/Fake Response Proxy_0.1.0_x64_en-US.msi`
- `nsis/Fake Response Proxy_0.1.0_x64-setup.exe`

Build release dùng LTO + strip → binary nhỏ (~7 MB).

---

## Cấu trúc thư mục

```
fake_response_proxy/
├── README.md                         ← bạn đang đọc
├── package.json                      ← Tauri CLI
├── examples/example_script.py        ← mẫu Python response script
├── scripts/gen-icons.ps1             ← script sinh icon từ placeholder
├── src/                              ← Frontend (vanilla HTML/CSS/JS)
│   ├── index.html
│   ├── style.css
│   └── main.js
└── src-tauri/
    ├── Cargo.toml
    ├── tauri.conf.json
    ├── build.rs
    ├── dev-server.py                 ← Python http.server cho dev mode
    ├── capabilities/default.json
    ├── icons/                        ← app icons (32x32, 128x128, ico, icns…)
    └── src/
        ├── main.rs
        ├── lib.rs                    ← Tauri Builder + setup
        ├── state.rs                  ← AppState
        ├── config.rs                 ← AppConfig + ListenerConfig
        ├── commands.rs               ← Tauri commands → JS
        ├── ca/                       ← Root CA + cert generation + install
        │   ├── mod.rs
        │   └── install.rs
        ├── proxy/                    ← HTTP/HTTPS proxy server
        │   ├── mod.rs                ← ProxyHandle (per-listener status)
        │   ├── server.rs             ← hyper + tokio-rustls
        │   └── tls.rs                ← DynamicResolver (per-SNI cert)
        ├── rules/                    ← rule matching
        ├── response/                 ← raw text / file / python script
        ├── storage/                  ← SQLite history
        └── divert/                   ← WinDivert redirect (Windows-only)
            ├── mod.rs
            ├── bootstrap.rs          ← auto-download/install WinDivert
            ├── ffi.rs                ← LoadLibrary wrapper
            └── redirector.rs         ← NAT loop + flow watcher
```

---

## Vị trí dữ liệu

`%APPDATA%\FakeResponseProxy\`:
- `config.json` — cấu hình listener + redirect + settings
- `rules.json` — danh sách response rule
- `history.sqlite` — request log (WAL mode)
- `ca\rootCA.pem` + `ca\rootCA.key` — **root CA private key** (đừng share!)

`%ProgramData%\FakeResponseProxy\windivert\` (chỉ tạo khi dùng Redirect tab):
- `WinDivert.dll`
- `WinDivert64.sys`

---

## Lưu ý bảo mật

- Root CA private key được lưu **plaintext trên đĩa**. Bất kỳ ai đọc được file `%APPDATA%\FakeResponseProxy\ca\rootCA.key` đều có thể tạo cert hợp lệ trên máy đã cài CA này. Hãy:
  - Chỉ cài CA vào trust store của máy bạn kiểm soát.
  - Uninstall CA khi không dùng app nữa.
- WinDivert chạy ở kernel mode, can thiệp packet trực tiếp. Chỉ chạy khi cần. Stop rule + Stop listener khi xong.
- App chỉ làm **MITM cho mục đích blocking telemetry / fake response cục bộ**. Đừng dùng để intercept traffic của user khác mà không có sự đồng ý.

---

## Khắc phục sự cố

| Lỗi | Nguyên nhân & Fix |
|-----|-------------------|
| Cửa sổ app trắng không có nội dung | WebView2 stuck → **Restart Windows**. |
| Listener fail "permission denied" | Port `<1024` cần admin → chạy app as Administrator. |
| `curl https://127.0.0.1` báo `SEC_E_WRONG_PRINCIPAL` | Cert SAN không match → đã fix bằng cert fallback IP. Stop+Start lại listener. |
| `curl` báo `CRYPT_E_NO_REVOCATION_CHECK` | Self-signed CA không có CRL/OCSP URL. Dùng `curl --ssl-no-revoke` để test. App đích thường dùng schannel sẽ tự skip nếu CA trust ở LocalMachine\Root. |
| Redirect rule "WinDivert: ..." | Driver chưa cài/load: vào tab Redirect → click Install WinDivert (cần admin). |
| Redirect rule `running` nhưng listener không nhận request, client báo timeout | Đang redirect tới `127.0.0.1` — Windows TCP stack có thể từ chối packet loopback NAT. **Đổi `redirect_to_ip` thành IP LAN thật của máy** (xem `ipconfig` → IPv4 Address, vd `10.x.y.z` / `192.168.x.y`) và bind listener `0.0.0.0:<port>` hoặc `<lan_ip>:<port>`. |
| Python script không chạy | Check Python ở PATH (`python --version`) hoặc set path trong Settings → Python interpreter. |

---

## License

Phát hành theo **[PolyForm Noncommercial License 1.0.0](LICENSE)** — mã nguồn công khai (source-available) nhưng **không phải** open source theo định nghĩa của OSI.

- ✅ Được phép: dùng cá nhân, nghiên cứu, học tập, thử nghiệm, sử dụng bởi tổ chức giáo dục / phi lợi nhuận / cơ quan nhà nước; sửa đổi và chia sẻ lại (kèm nguyên văn giấy phép và dòng `Required Notice`).
- ❌ Không được phép nếu chưa có giấy phép riêng: dùng cho mục đích thương mại hoặc trong hoạt động của doanh nghiệp, bán lại, đóng gói vào sản phẩm/dịch vụ thương mại hay mã nguồn đóng.

Cần dùng cho mục đích thương mại? Liên hệ tác giả (phongngan) để xin giấy phép thương mại riêng.

Thành phần bên thứ ba (Tauri, rustls, ... và WinDivert — tải về lúc chạy) giữ nguyên giấy phép gốc của từng dự án.
