//! Auto-install for WinDivert.
//!
//! Goal: end-user just runs the .exe. We:
//!   1. Verify admin elevation (relaunch with UAC if not).
//!   2. Resolve install dir (per-machine `%ProgramData%\FakeResponseProxy\windivert`
//!      by default; falls back to per-user if not writable).
//!   3. If `WinDivert.dll` + `WinDivert64.sys` are already there, done.
//!   4. Otherwise download the pinned WinDivert release zip, verify SHA-256,
//!      extract the two files we need.
//!
//! Driver registration (installing `WinDivert64.sys` as a kernel service) is
//! done automatically by `WinDivert.dll` on first `WinDivertOpen`, provided we
//! are elevated and the .sys file sits next to the .dll.

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Pinned WinDivert release. To bump: change the URL and the SHA-256 below
/// after independently verifying the published artifact.
pub const WINDIVERT_VERSION: &str = "2.2.2";
pub const WINDIVERT_URL: &str =
    "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";

/// SHA-256 of the WinDivert 2.2.2-A release zip.
///
/// IMPORTANT: this is a placeholder. Before shipping, replace it with the
/// hash you computed from the official GitHub release (or via
/// `Get-FileHash WinDivert-2.2.2-A.zip -Algorithm SHA256`). Leave the
/// placeholder during development by running with `FRP_SKIP_HASH=1`.
pub const WINDIVERT_ZIP_SHA256: &str =
    "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15";

#[derive(Debug, Clone)]
pub struct WinDivertPaths {
    pub install_dir: PathBuf,
    pub dll: PathBuf,
    pub sys: PathBuf,
}

/// Returns the install directory for WinDivert binaries. Prefers
/// `%ProgramData%\FakeResponseProxy\windivert`; falls back to LocalAppData
/// if ProgramData isn't writable (e.g. running unelevated in dev).
pub fn default_install_dir() -> PathBuf {
    if let Some(pd) = std::env::var_os("ProgramData").map(PathBuf::from) {
        return pd.join("FakeResponseProxy").join("windivert");
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("FakeResponseProxy")
        .join("windivert")
}

pub fn ensure_installed(install_dir: &Path) -> Result<WinDivertPaths> {
    fs::create_dir_all(install_dir)
        .with_context(|| format!("create dir {}", install_dir.display()))?;
    let paths = WinDivertPaths {
        install_dir: install_dir.to_path_buf(),
        dll: install_dir.join("WinDivert.dll"),
        sys: install_dir.join("WinDivert64.sys"),
    };
    if paths.dll.is_file() && paths.sys.is_file() {
        info!(
            version = WINDIVERT_VERSION,
            dir = %install_dir.display(),
            "WinDivert already installed"
        );
        return Ok(paths);
    }
    info!(url = WINDIVERT_URL, "downloading WinDivert {WINDIVERT_VERSION}");
    let zip_bytes = download(WINDIVERT_URL)?;
    if std::env::var_os("FRP_SKIP_HASH").is_some() {
        warn!("FRP_SKIP_HASH set — bypassing SHA-256 verification (dev only)");
    } else {
        verify_sha256(&zip_bytes, WINDIVERT_ZIP_SHA256)?;
    }
    extract(&zip_bytes, install_dir)?;
    if !paths.dll.is_file() || !paths.sys.is_file() {
        bail!(
            "post-extract: expected files missing from zip ({}, {})",
            paths.dll.display(),
            paths.sys.display()
        );
    }
    info!(dir = %install_dir.display(), "WinDivert installed");
    Ok(paths)
}

fn download(url: &str) -> Result<Vec<u8>> {
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(60))
        .call()
        .with_context(|| format!("HTTP GET {url}"))?;
    let len_hint = resp
        .header("Content-Length")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(512 * 1024);
    let mut buf = Vec::with_capacity(len_hint);
    // Hard cap at 20 MiB — the WinDivert zip is ~600 KiB.
    resp.into_reader()
        .take(20 * 1024 * 1024)
        .read_to_end(&mut buf)
        .context("read response body")?;
    info!(bytes = buf.len(), "download complete");
    Ok(buf)
}

fn verify_sha256(bytes: &[u8], expected_hex: &str) -> Result<()> {
    let actual = hex::encode(Sha256::digest(bytes));
    if !expected_hex.eq_ignore_ascii_case(&actual) {
        bail!(
            "WinDivert zip SHA-256 mismatch.\n  got:      {actual}\n  expected: {expected_hex}\n\
             Either update the pinned hash or set FRP_SKIP_HASH=1 (dev only)."
        );
    }
    info!("SHA-256 OK");
    Ok(())
}

fn extract(zip_bytes: &[u8], dest: &Path) -> Result<()> {
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut zip = zip::ZipArchive::new(cursor).context("open zip")?;
    let mut got_dll = false;
    let mut got_sys = false;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().replace('\\', "/");
        let basename = name.rsplit('/').next().unwrap_or("");
        // Only the 64-bit binaries.
        // The 2.2.x release ships WinDivert64.sys under x86/ (it's the kernel
        // driver, one per kernel arch — the parent folder name is misleading).
        let target = if name.contains("/x64/") && basename.eq_ignore_ascii_case("WinDivert.dll") {
            got_dll = true;
            Some(dest.join("WinDivert.dll"))
        } else if basename.eq_ignore_ascii_case("WinDivert64.sys") {
            got_sys = true;
            Some(dest.join("WinDivert64.sys"))
        } else {
            None
        };
        if let Some(out) = target {
            let mut data = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut data)?;
            write_atomic(&out, &data)
                .with_context(|| format!("write {}", out.display()))?;
            info!(path = %out.display(), bytes = data.len(), "extracted");
        }
    }
    if !got_dll || !got_sys {
        bail!("zip layout unexpected (dll={got_dll}, sys={got_sys}); pinned URL may be wrong");
    }
    Ok(())
}

fn write_atomic(out: &Path, data: &[u8]) -> Result<()> {
    let tmp = out.with_extension("tmp-download");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    // On Windows replace existing file atomically.
    fs::rename(&tmp, out)?;
    Ok(())
}

// --- Elevation -----------------------------------------------------------

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev: TOKEN_ELEVATION = zeroed();
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

/// Relaunch the current executable with UAC elevation, exiting the current
/// (unelevated) process. Returns Err if the user declines or relaunch fails.
#[cfg(windows)]
pub fn relaunch_elevated() -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::{ShellExecuteW, SE_ERR_ACCESSDENIED, SHELLEXECUTEINFOW};
    let exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args_joined = args
        .iter()
        .map(|a| {
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let verb: Vec<u16> = std::ffi::OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let file: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let params_os = std::ffi::OsString::from(args_joined);
    let params: Vec<u16> = params_os.encode_wide().chain(std::iter::once(0)).collect();

    let h = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            5, // SW_SHOW
        )
    };
    // ShellExecuteW returns an HINSTANCE; values <= 32 are errors.
    if (h as isize) <= 32 {
        let code = h as isize;
        if code == SE_ERR_ACCESSDENIED as isize {
            bail!("user declined the UAC prompt");
        }
        bail!("ShellExecuteW failed (code {code})");
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<()> {
    bail!("relaunch_elevated is Windows-only");
}
