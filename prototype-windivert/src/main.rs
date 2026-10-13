//! Prototype: redirect outbound TCP to a local proxy using WinDivert.
//!
//! Self-bootstrapping: on first launch the exe checks for WinDivert.dll +
//! WinDivert64.sys in `%ProgramData%\FakeResponseProxy\windivert`. If absent
//! it downloads the pinned WinDivert release, verifies SHA-256, and extracts
//! the two needed files. If launched without admin it self-elevates via UAC.
//!
//! Default mode redirects traffic from ALL processes whose outbound connection
//! has `dst_port == --target-port`. Use `--process <name.exe>` to restrict.
//!
//! Example:
//!     windivert-redirect.exe --target-port 443 --listen-port 18443
//!     windivert-redirect.exe --target-port 443 --listen-port 18443 --process target.exe

use anyhow::{anyhow, Result};
use clap::Parser;
use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

mod bootstrap;
mod divert;
use divert::{Direction, DivertHandle, FlowEvent, Layer};

#[derive(Parser, Debug, Clone)]
#[command(version, about = "Prototype WinDivert TCP redirect")]
struct Args {
    /// External port to intercept (the port the target app thinks it's hitting).
    #[arg(long, default_value_t = 443)]
    target_port: u16,

    /// Local proxy port that will receive redirected traffic on 127.0.0.1.
    #[arg(long, default_value_t = 18443)]
    listen_port: u16,

    /// Optional process name (case-insensitive, e.g. "target.exe").
    /// When omitted, redirect applies to ALL processes.
    #[arg(long)]
    process: Option<String>,

    /// Override the directory where WinDivert.dll + WinDivert64.sys live.
    /// Defaults to %ProgramData%\FakeResponseProxy\windivert.
    #[arg(long)]
    windivert_dir: Option<PathBuf>,

    /// Skip the auto-relaunch under UAC when not elevated. Useful if you
    /// already launched from an elevated shell.
    #[arg(long)]
    no_uac: bool,
}

#[derive(Clone, Copy, Debug)]
struct ConnState {
    orig_src_ip: Ipv4Addr,
    orig_dst_ip: Ipv4Addr,
    orig_dst_port: u16,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "windivert_redirect=info,warn".into()),
        )
        .init();

    let args = Args::parse();
    info!(?args, "starting");

    // 1. Elevation check. Without admin we can't load the kernel driver, can't
    //    write to ProgramData, and can't intercept system traffic.
    if !bootstrap::is_elevated() {
        if args.no_uac {
            return Err(anyhow!(
                "not elevated and --no-uac is set; relaunch as Administrator"
            ));
        }
        warn!("not elevated, requesting UAC and exiting current process");
        bootstrap::relaunch_elevated()?;
        return Ok(());
    }

    // 2. Make sure WinDivert.dll + WinDivert64.sys are on disk. Download +
    //    verify SHA-256 + extract if missing. End-user does nothing.
    let install_dir = args
        .windivert_dir
        .clone()
        .unwrap_or_else(bootstrap::default_install_dir);
    let paths = bootstrap::ensure_installed(&install_dir)?;

    // 3. Resolve all WinDivert entry points from the downloaded DLL.
    divert::init(&paths.dll)?;

    // src_port -> connection state for reply rewrite
    let table: Arc<DashMap<u16, ConnState>> = Arc::new(DashMap::new());

    // Filter catches both directions in one handle:
    //   forward : outbound, app -> X:target_port (excluding local already-on-loopback)
    //   reverse : loopback, proxy -> client on tcp.SrcPort == listen_port
    let filter = format!(
        "(ip and tcp and outbound and tcp.DstPort == {tp} and ip.DstAddr != 127.0.0.1) \
         or (ip and tcp and loopback and tcp.SrcPort == {lp})",
        tp = args.target_port,
        lp = args.listen_port,
    );
    info!(%filter, "opening WinDivert NETWORK layer");
    let handle = DivertHandle::open(&filter, Layer::Network, 0, 0)?;

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = running.clone();
        let handle = handle.clone();
        ctrlc::set_handler(move || {
            warn!("Ctrl-C received, shutting down");
            running.store(false, Ordering::SeqCst);
            let _ = handle.shutdown();
        })?;
    }

    // Optional process whitelist via FLOW layer.
    let whitelist: Option<Arc<DashMap<u16, ()>>> = match args.process.as_deref() {
        Some(name) => {
            let wl: Arc<DashMap<u16, ()>> = Arc::new(DashMap::new());
            spawn_flow_watcher(name.to_string(), wl.clone(), running.clone())?;
            Some(wl)
        }
        None => None,
    };

    let mut buf = vec![0u8; 0xFFFF];
    while running.load(Ordering::SeqCst) {
        let (len, mut addr) = match handle.recv(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                warn!("recv error: {e}");
                continue;
            }
        };

        let modified = match rewrite_packet(
            &mut buf[..len],
            &mut addr,
            &args,
            &table,
            whitelist.as_deref(),
        ) {
            Ok(m) => m,
            Err(e) => {
                debug!("rewrite error, passthrough: {e}");
                false
            }
        };
        let _ = modified;

        if let Err(e) = handle.send(&buf[..len], &addr) {
            debug!("send error: {e}");
        }
    }

    info!("stopped");
    Ok(())
}

/// Returns Ok(true) if buffer/addr were modified, Ok(false) if unchanged.
fn rewrite_packet(
    pkt: &mut [u8],
    addr: &mut divert::Address,
    args: &Args,
    table: &DashMap<u16, ConnState>,
    whitelist: Option<&DashMap<u16, ()>>,
) -> Result<bool> {
    if pkt.len() < 20 {
        return Ok(false);
    }
    // IPv4 only (skip IPv6 in prototype).
    let version = pkt[0] >> 4;
    if version != 4 {
        return Ok(false);
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if pkt.len() < ihl + 20 {
        return Ok(false);
    }
    // protocol == TCP?
    if pkt[9] != 6 {
        return Ok(false);
    }
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let tcp = &pkt[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let tcp_flags = tcp[13];

    let dir = addr.direction();

    if dir == Direction::Outbound && !addr.is_loopback() && dst_port == args.target_port {
        if let Some(wl) = whitelist {
            if !wl.contains_key(&src_port) {
                debug!(src_port, "skip: src_port not in whitelist");
                return Ok(false);
            }
        }
        table.insert(
            src_port,
            ConnState {
                orig_src_ip: src_ip,
                orig_dst_ip: dst_ip,
                orig_dst_port: dst_port,
            },
        );
        info!(
            from = %format!("{src_ip}:{src_port}"),
            to   = %format!("{dst_ip}:{dst_port}"),
            via  = %format!("127.0.0.1:{}", args.listen_port),
            "redirect"
        );
        // src=127.0.0.1, dst=127.0.0.1:listen_port → loopback delivery
        write_u32(&mut pkt[12..16], Ipv4Addr::LOCALHOST);
        write_u32(&mut pkt[16..20], Ipv4Addr::LOCALHOST);
        write_u16(&mut pkt[ihl + 2..ihl + 4], args.listen_port);
        addr.set_loopback(true);
        addr.set_direction(Direction::Outbound);
        divert::calc_checksums(pkt)?;
        Ok(true)
    } else if addr.is_loopback() && src_port == args.listen_port {
        // Reply on loopback from proxy. dst_port == original src_port.
        let key = dst_port;
        let Some(state) = table.get(&key).map(|v| *v) else {
            return Ok(false);
        };
        debug!(
            proxy_src = %format!("127.0.0.1:{src_port}"),
            client    = %format!("127.0.0.1:{dst_port}"),
            restore_src = %format!("{}:{}", state.orig_dst_ip, state.orig_dst_port),
            restore_dst = %format!("{}:{}", state.orig_src_ip, key),
            "unredirect"
        );
        write_u32(&mut pkt[12..16], state.orig_dst_ip);
        write_u32(&mut pkt[16..20], state.orig_src_ip);
        write_u16(&mut pkt[ihl..ihl + 2], state.orig_dst_port);
        // Hand it to the app stack as an incoming packet.
        addr.set_loopback(false);
        addr.set_direction(Direction::Inbound);
        divert::calc_checksums(pkt)?;
        // FIN or RST closes the mapping.
        if tcp_flags & 0b0000_0101 != 0 {
            table.remove(&key);
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

fn write_u32(dst: &mut [u8], ip: Ipv4Addr) {
    dst.copy_from_slice(&ip.octets());
}
fn write_u16(dst: &mut [u8], v: u16) {
    dst.copy_from_slice(&v.to_be_bytes());
}

// --- FLOW layer watcher: maintain a whitelist of src_port owned by target process ---

fn spawn_flow_watcher(
    target_process: String,
    whitelist: Arc<DashMap<u16, ()>>,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let target_lower = target_process.to_ascii_lowercase();
    let pid_cache: Arc<DashMap<u32, bool>> = Arc::new(DashMap::new());

    std::thread::spawn(move || {
        let handle = match DivertHandle::open_flow_sniff("true") {
            Ok(h) => h,
            Err(e) => {
                error!("FLOW open failed: {e}");
                return;
            }
        };
        while running.load(Ordering::SeqCst) {
            match handle.recv_flow() {
                Ok(ev) => {
                    let matches = *pid_cache
                        .entry(ev.pid)
                        .or_insert_with(|| process_name_matches(ev.pid, &target_lower));
                    if !matches {
                        continue;
                    }
                    match ev.event {
                        FlowEvent::Established => {
                            whitelist.insert(ev.local_port, ());
                            info!(pid = ev.pid, port = ev.local_port, "whitelist +");
                        }
                        FlowEvent::Deleted => {
                            whitelist.remove(&ev.local_port);
                        }
                    }
                }
                Err(e) => {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    debug!("flow recv: {e}");
                }
            }
        }
    });
    Ok(())
}

#[cfg(windows)]
fn process_name_matches(pid: u32, target_lower: &str) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut buf = [0u16; 1024];
        let mut len: u32 = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return false;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]).to_ascii_lowercase();
        path.rsplit(|c| c == '\\' || c == '/')
            .next()
            .map(|n| n == target_lower)
            .unwrap_or(false)
    }
}

#[cfg(not(windows))]
fn process_name_matches(_pid: u32, _target_lower: &str) -> bool {
    false
}
