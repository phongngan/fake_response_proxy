//! Auto-installer for the WinDivert binaries.
//!
//! On first need we make sure `WinDivert.dll` + `WinDivert64.sys` exist in
//! `%ProgramData%\FakeResponseProxy\windivert`. If absent we download the
//! pinned release zip from GitHub, verify SHA-256, and extract the two
//! files. End-user does nothing.
//!
//! Driver registration (installing `WinDivert64.sys` as a kernel service) is
//! handled automatically by `WinDivert.dll` on first `WinDivertOpen`, provided
//! the process is elevated and the .sys file sits next to the .dll.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

pub const WINDIVERT_VERSION: &str = "2.2.2";
pub const WINDIVERT_URL: &str =
    "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";

/// SHA-256 of the WinDivert 2.2.2-A release zip (computed from
/// github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip,
/// 405 137 bytes). Recompute and update when bumping `WINDIVERT_VERSION`.
pub const WINDIVERT_ZIP_SHA256: &str =
    "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15";

#[derive(Debug, Clone)]
pub struct WinDivertPaths {
    pub install_dir: PathBuf,
    pub dll: PathBuf,
    pub sys: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallState {
    Missing,
    Downloading,
    Installed,
    Failed,
}

#[derive(Default)]
struct InstallSlot {
    state: AtomicU8, // 0=missing, 1=downloading, 2=installed, 3=failed
}

impl InstallSlot {
    fn load(&self) -> InstallState {
        match self.state.load(Ordering::SeqCst) {
            0 => InstallState::Missing,
            1 => InstallState::Downloading,
            2 => InstallState::Installed,
            _ => InstallState::Failed,
        }
    }
    fn store(&self, s: InstallState) {
        let v = match s {
            InstallState::Missing => 0,
            InstallState::Downloading => 1,
            InstallState::Installed => 2,
            InstallState::Failed => 3,
        };
        self.state.store(v, Ordering::SeqCst);
    }
}

/// Process-wide install tracker. Cheap to clone (Arc).
#[derive(Clone, Default)]
pub struct Tracker(Arc<InstallSlot>);

impl Tracker {
    pub fn state(&self) -> InstallState {
        self.0.load()
    }
    fn set(&self, s: InstallState) {
        self.0.store(s);
    }
}

/// `%ProgramData%\FakeResponseProxy\windivert` by default.
pub fn default_install_dir() -> PathBuf {
    if let Some(pd) = std::env::var_os("ProgramData").map(PathBuf::from) {
        return pd.join("FakeResponseProxy").join("windivert");
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("FakeResponseProxy")
        .join("windivert")
}

pub fn paths(install_dir: &Path) -> WinDivertPaths {
    WinDivertPaths {
        install_dir: install_dir.to_path_buf(),
        dll: install_dir.join("WinDivert.dll"),
        sys: install_dir.join("WinDivert64.sys"),
    }
}

pub fn is_installed(install_dir: &Path) -> bool {
    let p = paths(install_dir);
    p.dll.is_file() && p.sys.is_file()
}

pub fn ensure_installed(install_dir: &Path, tracker: &Tracker) -> Result<WinDivertPaths> {
    fs::create_dir_all(install_dir)
        .with_context(|| format!("create dir {}", install_dir.display()))?;
    let p = paths(install_dir);
    if p.dll.is_file() && p.sys.is_file() {
        tracker.set(InstallState::Installed);
        info!(
            version = WINDIVERT_VERSION,
            dir = %install_dir.display(),
            "WinDivert already installed"
        );
        return Ok(p);
    }
    tracker.set(InstallState::Downloading);
    let result = (|| -> Result<()> {
        info!(url = WINDIVERT_URL, "downloading WinDivert {WINDIVERT_VERSION}");
        let zip_bytes = download(WINDIVERT_URL)?;
        if std::env::var_os("FRP_SKIP_HASH").is_some() {
            warn!("FRP_SKIP_HASH set — bypassing SHA-256 verification (dev only)");
        } else {
            verify_sha256(&zip_bytes, WINDIVERT_ZIP_SHA256)?;
        }
        extract(&zip_bytes, install_dir)
    })();
    match result {
        Ok(()) => {
            if !p.dll.is_file() || !p.sys.is_file() {
                tracker.set(InstallState::Failed);
                bail!(
                    "post-extract: expected files missing from zip ({}, {})",
                    p.dll.display(),
                    p.sys.display()
                );
            }
            tracker.set(InstallState::Installed);
            info!(dir = %install_dir.display(), "WinDivert installed");
            Ok(p)
        }
        Err(e) => {
            tracker.set(InstallState::Failed);
            Err(e)
        }
    }
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
             Update the pinned hash or set FRP_SKIP_HASH=1 (dev only)."
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
        // The 2.2.x release ships WinDivert64.sys under x86/ (it's the kernel
        // driver, one per kernel arch — the parent folder name is misleading).
        // The user-mode DLL we want is the 64-bit one under x64/.
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
    fs::rename(&tmp, out)?;
    Ok(())
}

// --- UAC self-elevation -------------------------------------------------

/// Relaunch the current executable elevated. The caller should exit shortly
/// after a successful return so the unelevated parent goes away.
#[cfg(windows)]
pub fn relaunch_elevated() -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::{ShellExecuteW, SE_ERR_ACCESSDENIED};
    let exe = std::env::current_exe()?;
    let args_joined = std::env::args()
        .skip(1)
        .map(|a| {
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a
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
    let params: Vec<u16> =
        params_os.encode_wide().chain(std::iter::once(0)).collect();

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
