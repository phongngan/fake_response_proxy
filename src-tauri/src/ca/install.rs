//! Install / uninstall the root CA into Windows' trust store.
//!
//! We shell out to `certutil.exe` because it ships with Windows and handles
//! UAC elevation when invoked from an elevated process. For LocalMachine\Root
//! the process must already be elevated. We surface a clear error otherwise.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Install the CA PEM at `cert_path` into LocalMachine\Root.
/// Requires the current process to be elevated (admin).
pub fn install_to_system_root(cert_path: &Path) -> Result<()> {
    run_certutil(&["-addstore", "Root", &cert_path.to_string_lossy()])
        .context("certutil -addstore Root")?;
    Ok(())
}

/// Install the CA PEM at `cert_path` into CurrentUser\Root (no admin needed,
/// but only this user trusts it).
pub fn install_to_user_root(cert_path: &Path) -> Result<()> {
    run_certutil(&[
        "-user",
        "-addstore",
        "Root",
        &cert_path.to_string_lossy(),
    ])
    .context("certutil -user -addstore Root")?;
    Ok(())
}

/// Remove by CN. Best-effort.
pub fn uninstall_system_root(common_name: &str) -> Result<()> {
    run_certutil(&["-delstore", "Root", common_name])
        .context("certutil -delstore Root")?;
    Ok(())
}

pub fn uninstall_user_root(common_name: &str) -> Result<()> {
    run_certutil(&["-user", "-delstore", "Root", common_name])
        .context("certutil -user -delstore Root")?;
    Ok(())
}

/// Check whether a certificate with the given SHA-1 thumbprint is installed
/// in `CurrentUser\Root`.
pub fn is_in_user_root(thumbprint_hex: &str) -> bool {
    cert_in_store(true, thumbprint_hex)
}

/// Check whether a certificate with the given SHA-1 thumbprint is installed
/// in `LocalMachine\Root`. Read-only access does NOT require admin.
pub fn is_in_system_root(thumbprint_hex: &str) -> bool {
    cert_in_store(false, thumbprint_hex)
}

fn cert_in_store(user_scope: bool, thumbprint_hex: &str) -> bool {
    let mut args: Vec<&str> = Vec::new();
    if user_scope {
        args.push("-user");
    }
    args.push("-store");
    args.push("Root");
    args.push(thumbprint_hex);
    let mut cmd = Command::new("certutil");
    cmd.args(&args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    match cmd.output() {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

fn run_certutil(args: &[&str]) -> Result<()> {
    let mut cmd = Command::new("certutil");
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd.output().context("spawn certutil.exe")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        anyhow::bail!(
            "certutil failed (exit {:?}): {}{}",
            out.status.code(),
            stdout,
            stderr
        );
    }
    Ok(())
}
