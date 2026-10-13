//! Execute a user-provided Python script:
//! 1. Write the raw request to a temp file.
//! 2. Spawn `<python> <script> [args...] <req_temp_file>`.
//! 3. The script must print (stdout) the absolute path of the response file it wrote.
//! 4. We read that response file, then delete both temp files.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub async fn run<'a, I>(
    python: Option<&str>,
    script: &str,
    args: I,
    request_raw: &str,
) -> Result<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let tmp_dir = std::env::temp_dir().join("fake-response-proxy");
    fs::create_dir_all(&tmp_dir).await.ok();
    let id = uuid::Uuid::new_v4();
    let req_path = tmp_dir.join(format!("req_{id}.txt"));

    // Write request to temp.
    {
        let mut f = fs::File::create(&req_path)
            .await
            .with_context(|| format!("create {}", req_path.display()))?;
        f.write_all(request_raw.as_bytes()).await?;
        f.flush().await?;
    }

    let py = python.unwrap_or("python");
    let mut cmd = Command::new(py);
    cmd.arg(script);
    for a in args {
        cmd.arg(a);
    }
    cmd.arg(&req_path);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        // tokio::process::Command has inherent creation_flags on Windows.
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }

    let out = cmd
        .output()
        .await
        .with_context(|| format!("spawn python script: {py} {script}"))?;

    // Always try to clean up the request temp.
    let _ = fs::remove_file(&req_path).await;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!(
            "python script failed (exit {:?}): {}",
            out.status.code(),
            stderr.trim()
        );
    }

    let resp_path_str = String::from_utf8_lossy(&out.stdout)
        .trim()
        .to_string();
    if resp_path_str.is_empty() {
        anyhow::bail!("python script did not print a response file path on stdout");
    }
    let resp_path = PathBuf::from(&resp_path_str);
    let response_raw = fs::read_to_string(&resp_path)
        .await
        .with_context(|| format!("read response file: {resp_path_str}"))?;
    let _ = fs::remove_file(&resp_path).await;
    Ok(response_raw)
}
