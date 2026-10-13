//! Lifecycle manager for redirect rules.
//!
//! Each [`RedirectRule`] becomes one or two threads:
//!   - one NAT loop on a WinDivert NETWORK-layer handle (always present)
//!   - one FLOW-layer watcher (only if `process` filter is set), feeding a
//!     port->ok whitelist consulted by the NAT loop.
//!
//! Threads stay alive until [`RedirectorHandle::stop_rule`] (or `stop_all`)
//! flips an atomic stop flag and shuts the WinDivert handle so blocked recv
//! calls unblock.

use crate::divert::{bootstrap, ffi};
use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tracing::{debug, info, warn};

/// User-configurable redirect rule, persisted in `AppConfig.redirects`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// Destination port to intercept on outbound traffic (e.g. 443).
    pub target_port: u16,
    /// Local proxy port (or remote port) to redirect to.
    pub listen_port: u16,
    /// Optional process-name filter (case-insensitive). None = all processes.
    pub process: Option<String>,
    /// Comma-separated destinations to match. Each entry is an IPv4 literal
    /// (e.g. "1.2.3.4") or a hostname (e.g. "evil.example.com"). Hostnames
    /// are resolved on rule start. Empty string = match any destination IP
    /// (subject to other filters).
    #[serde(default)]
    pub target: String,
    /// IP to rewrite the destination to. Default "127.0.0.1".
    /// Use 127.x.x.x for a local proxy on the same machine, or any other IPv4
    /// to forward to a remote host.
    #[serde(default = "default_redirect_ip")]
    pub redirect_to_ip: String,
}

fn default_redirect_ip() -> String {
    "127.0.0.1".into()
}

impl Default for RedirectRule {
    fn default() -> Self {
        Self {
            id: format!("redir-{}", uuid::Uuid::new_v4().simple()),
            name: "New redirect".into(),
            enabled: false,
            target_port: 443,
            listen_port: 18443,
            process: None,
            target: String::new(),
            redirect_to_ip: default_redirect_ip(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleState {
    Stopped,
    Running,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleRuntimeState {
    pub id: String,
    pub state: RuleState,
    pub error: Option<String>,
    /// Live count of in-flight connections being tracked for reply rewriting.
    pub active_connections: u64,
    /// Bytes intercepted on the forward path. Cheap counter, not exact.
    pub forwarded_packets: u64,
    /// IPv4 addresses the `target` field resolved to when the rule started.
    /// Empty = match any destination IP.
    pub resolved_targets: Vec<String>,
    /// The redirect destination IP after parsing.
    pub redirect_to_ip: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedirectStatus {
    pub install_state: bootstrap::InstallState,
    pub install_dir: String,
    pub windivert_version: String,
    pub rules: Vec<RuleRuntimeState>,
}

#[derive(Clone, Copy)]
struct ConnState {
    orig_src_ip: Ipv4Addr,
    orig_dst_ip: Ipv4Addr,
    orig_dst_port: u16,
}

struct RuleEntry {
    stop: Arc<AtomicBool>,
    handle: ffi::DivertHandle,
    flow_handle: Option<ffi::DivertHandle>,
    thread: Option<JoinHandle<()>>,
    flow_thread: Option<JoinHandle<()>>,
    table: Arc<DashMap<u16, ConnState>>,
    counter: Arc<AtomicU64>,
    error: Option<String>,
    resolved_targets: Vec<Ipv4Addr>,
    redirect_to_ip: Ipv4Addr,
}

pub struct RedirectorHandle {
    install_dir: PathBuf,
    tracker: bootstrap::Tracker,
    init_lock: Mutex<()>,
    rules: Mutex<HashMap<String, RuleEntry>>,
}

impl RedirectorHandle {
    pub fn new(install_dir: PathBuf) -> Self {
        Self {
            install_dir,
            tracker: bootstrap::Tracker::default(),
            init_lock: Mutex::new(()),
            rules: Mutex::new(HashMap::new()),
        }
    }

    pub fn install_dir(&self) -> &Path {
        &self.install_dir
    }

    /// Ensure WinDivert.dll + .sys exist on disk and the DLL is loaded.
    /// Idempotent. The first call may take a few seconds (download).
    pub fn ensure_ready(&self) -> Result<()> {
        let _g = self.init_lock.lock();
        if ffi::is_initialized() {
            return Ok(());
        }
        let paths = bootstrap::ensure_installed(&self.install_dir, &self.tracker)?;
        ffi::init(&paths.dll)?;
        Ok(())
    }

    /// Just download/extract without loading — useful for an explicit
    /// "Install WinDivert" button before the user enables any rules.
    pub fn ensure_downloaded(&self) -> Result<()> {
        let _ = bootstrap::ensure_installed(&self.install_dir, &self.tracker)?;
        Ok(())
    }

    pub fn status(&self) -> RedirectStatus {
        let install_state = if ffi::is_initialized() || bootstrap::is_installed(&self.install_dir) {
            bootstrap::InstallState::Installed
        } else {
            self.tracker.state()
        };
        let g = self.rules.lock();
        let mut rules: Vec<RuleRuntimeState> = g
            .iter()
            .map(|(id, e)| RuleRuntimeState {
                id: id.clone(),
                state: if e.error.is_some() {
                    RuleState::Failed
                } else {
                    RuleState::Running
                },
                error: e.error.clone(),
                active_connections: e.table.len() as u64,
                forwarded_packets: e.counter.load(Ordering::Relaxed),
                resolved_targets: e
                    .resolved_targets
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect(),
                redirect_to_ip: e.redirect_to_ip.to_string(),
            })
            .collect();
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        RedirectStatus {
            install_state,
            install_dir: self.install_dir.to_string_lossy().into_owned(),
            windivert_version: bootstrap::WINDIVERT_VERSION.into(),
            rules,
        }
    }

    pub fn start_rule(&self, rule: &RedirectRule) -> Result<()> {
        self.stop_rule(&rule.id);
        self.ensure_ready()?;

        let redirect_to_ip: Ipv4Addr = rule
            .redirect_to_ip
            .trim()
            .parse()
            .with_context(|| format!("invalid redirect_to_ip '{}'", rule.redirect_to_ip))?;
        let resolved_targets = resolve_targets(&rule.target)?;
        if !rule.target.trim().is_empty() && resolved_targets.is_empty() {
            return Err(anyhow!(
                "target '{}' resolved to no IPv4 addresses",
                rule.target
            ));
        }

        let filter = build_filter(
            &resolved_targets,
            rule.target_port,
            redirect_to_ip,
            rule.listen_port,
        );
        info!(rule_id = %rule.id, %filter, "opening WinDivert handle");
        let handle = ffi::DivertHandle::open(&filter, ffi::Layer::Network, 0, 0)?;

        let table: Arc<DashMap<u16, ConnState>> = Arc::new(DashMap::new());
        let counter = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let whitelist: Option<Arc<DashMap<u16, ()>>> =
            rule.process.as_ref().map(|_| Arc::new(DashMap::new()));

        let mut entry = RuleEntry {
            stop: stop.clone(),
            handle: handle.clone(),
            flow_handle: None,
            thread: None,
            flow_thread: None,
            table: table.clone(),
            counter: counter.clone(),
            error: None,
            resolved_targets: resolved_targets.clone(),
            redirect_to_ip,
        };

        if let Some(name) = rule.process.clone() {
            let flow_h = ffi::DivertHandle::open_flow_sniff("true")?;
            entry.flow_handle = Some(flow_h.clone());
            let wl = whitelist.as_ref().unwrap().clone();
            let stop_f = stop.clone();
            let rid = rule.id.clone();
            let t = std::thread::Builder::new()
                .name(format!("frp-divert-flow-{}", rule.id))
                .spawn(move || flow_watcher(flow_h, name, wl, stop_f, rid))?;
            entry.flow_thread = Some(t);
        }

        let nat_cfg = NatCfg {
            target_port: rule.target_port,
            listen_port: rule.listen_port,
            redirect_to_ip,
            resolved_targets,
            rule_id: rule.id.clone(),
        };
        let table_w = table.clone();
        let counter_w = counter.clone();
        let stop_w = stop.clone();
        let wl_w = whitelist.clone();
        let handle_w = handle.clone();
        let t = std::thread::Builder::new()
            .name(format!("frp-divert-nat-{}", rule.id))
            .spawn(move || nat_loop(handle_w, nat_cfg, table_w, wl_w, counter_w, stop_w))?;
        entry.thread = Some(t);

        let mut g = self.rules.lock();
        g.insert(rule.id.clone(), entry);
        Ok(())
    }

    pub fn stop_rule(&self, id: &str) {
        let entry = {
            let mut g = self.rules.lock();
            g.remove(id)
        };
        let Some(mut entry) = entry else { return };
        entry.stop.store(true, Ordering::SeqCst);
        let _ = entry.handle.shutdown();
        if let Some(fh) = &entry.flow_handle {
            let _ = fh.shutdown();
        }
        if let Some(t) = entry.thread.take() {
            let _ = t.join();
        }
        if let Some(t) = entry.flow_thread.take() {
            let _ = t.join();
        }
        info!(rule_id = %id, "redirect rule stopped");
    }

    pub fn stop_all(&self) {
        let ids: Vec<String> = self.rules.lock().keys().cloned().collect();
        for id in ids {
            self.stop_rule(&id);
        }
    }
}

#[derive(Clone)]
struct NatCfg {
    target_port: u16,
    listen_port: u16,
    redirect_to_ip: Ipv4Addr,
    /// Empty = any destination IP allowed (subject to filter).
    resolved_targets: Vec<Ipv4Addr>,
    rule_id: String,
}

impl NatCfg {
    #[inline]
    fn is_loopback_redirect(&self) -> bool {
        self.redirect_to_ip.octets()[0] == 127
    }
    #[inline]
    fn target_matches(&self, ip: Ipv4Addr) -> bool {
        self.resolved_targets.is_empty() || self.resolved_targets.contains(&ip)
    }
}

fn nat_loop(
    handle: ffi::DivertHandle,
    cfg: NatCfg,
    table: Arc<DashMap<u16, ConnState>>,
    whitelist: Option<Arc<DashMap<u16, ()>>>,
    counter: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) {
    let mut buf = vec![0u8; 0xFFFF];
    while !stop.load(Ordering::SeqCst) {
        let (len, mut addr) = match handle.recv(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                debug!(rule_id = %cfg.rule_id, "recv error: {e}");
                continue;
            }
        };
        let modified =
            rewrite_packet(&mut buf[..len], &mut addr, &cfg, &table, whitelist.as_deref())
                .unwrap_or(false);
        if modified {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        if let Err(e) = handle.send(&buf[..len], &addr) {
            debug!(rule_id = %cfg.rule_id, "send error: {e}");
        }
    }
    info!(rule_id = %cfg.rule_id, "NAT loop exited");
}

fn rewrite_packet(
    pkt: &mut [u8],
    addr: &mut ffi::Address,
    cfg: &NatCfg,
    table: &DashMap<u16, ConnState>,
    whitelist: Option<&DashMap<u16, ()>>,
) -> Result<bool> {
    if pkt.len() < 20 {
        return Ok(false);
    }
    if (pkt[0] >> 4) != 4 {
        return Ok(false);
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if pkt.len() < ihl + 20 {
        return Ok(false);
    }
    if pkt[9] != 6 {
        return Ok(false);
    }
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    let tcp_flags = pkt[ihl + 13];

    let dir = addr.direction();

    // Forward path: outbound app -> external server.
    // Reject packets we already redirected (dst == redirect target).
    let already_redirected =
        dst_ip == cfg.redirect_to_ip && dst_port == cfg.listen_port;
    let port_match = cfg.target_port == 0 || dst_port == cfg.target_port;
    let is_forward = dir == ffi::Direction::Outbound
        && !addr.is_loopback()
        && port_match
        && cfg.target_matches(dst_ip)
        && !already_redirected;

    // Reverse path: response from redirect target back to the app.
    let is_reverse = src_ip == cfg.redirect_to_ip && src_port == cfg.listen_port;

    if is_forward {
        if let Some(wl) = whitelist {
            if !wl.contains_key(&src_port) {
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
        // For loopback redirect we also rewrite src IP so the reply naturally
        // comes back over loopback. For a remote redirect target, keep src
        // unchanged so the remote machine sends the reply to our real address.
        if cfg.is_loopback_redirect() {
            pkt[12..16].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
        }
        pkt[16..20].copy_from_slice(&cfg.redirect_to_ip.octets());
        pkt[ihl + 2..ihl + 4].copy_from_slice(&cfg.listen_port.to_be_bytes());
        addr.set_loopback(cfg.is_loopback_redirect());
        addr.set_direction(ffi::Direction::Outbound);
        ffi::calc_checksums(pkt)?;
        Ok(true)
    } else if is_reverse {
        let key = dst_port;
        let Some(state) = table.get(&key).map(|v| *v) else {
            return Ok(false);
        };
        pkt[12..16].copy_from_slice(&state.orig_dst_ip.octets());
        pkt[16..20].copy_from_slice(&state.orig_src_ip.octets());
        pkt[ihl..ihl + 2].copy_from_slice(&state.orig_dst_port.to_be_bytes());
        addr.set_loopback(false);
        addr.set_direction(ffi::Direction::Inbound);
        ffi::calc_checksums(pkt)?;
        if tcp_flags & 0b0000_0101 != 0 {
            table.remove(&key);
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Build a WinDivert filter expression for a redirect rule.
/// Catches both forward (outbound to one of `targets`) and reverse (any packet
/// whose src is the redirect destination).
fn build_filter(
    targets: &[Ipv4Addr],
    target_port: u16,
    redirect_to_ip: Ipv4Addr,
    listen_port: u16,
) -> String {
    let target_clause = if targets.is_empty() {
        // Match any except the redirect target itself (avoids re-triggering on
        // our own rewrites) and loopback.
        format!(
            "ip.DstAddr != 127.0.0.1 and ip.DstAddr != {}",
            redirect_to_ip
        )
    } else {
        let ors: Vec<String> = targets
            .iter()
            .map(|ip| format!("ip.DstAddr == {ip}"))
            .collect();
        format!("({})", ors.join(" or "))
    };
    let port_clause = if target_port == 0 {
        String::new()
    } else {
        format!(" and tcp.DstPort == {target_port}")
    };
    let forward = format!("ip and tcp and outbound and {target_clause}{port_clause}");
    let reverse = format!(
        "ip and tcp and ip.SrcAddr == {} and tcp.SrcPort == {}",
        redirect_to_ip, listen_port
    );
    format!("({forward}) or ({reverse})")
}

/// Resolve a comma-separated list of IPv4 addresses or hostnames into IPv4 set.
fn resolve_targets(target: &str) -> Result<Vec<Ipv4Addr>> {
    let target = target.trim();
    if target.is_empty() {
        return Ok(Vec::new());
    }
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for entry in target.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if let Ok(ip) = entry.parse::<Ipv4Addr>() {
            out.push(ip);
            continue;
        }
        let addrs = (entry, 0u16)
            .to_socket_addrs()
            .with_context(|| format!("resolve hostname '{entry}'"))?;
        let mut any = false;
        for sa in addrs {
            if let SocketAddr::V4(v4) = sa {
                out.push(*v4.ip());
                any = true;
            }
        }
        if !any {
            warn!(host = %entry, "no IPv4 records for hostname");
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn flow_watcher(
    handle: ffi::DivertHandle,
    target_process: String,
    whitelist: Arc<DashMap<u16, ()>>,
    stop: Arc<AtomicBool>,
    rule_id: String,
) {
    let target_lower = target_process.to_ascii_lowercase();
    let pid_cache: DashMap<u32, bool> = DashMap::new();
    while !stop.load(Ordering::SeqCst) {
        let ev = match handle.recv_flow() {
            Ok(e) => e,
            Err(_) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                continue;
            }
        };
        let matches = *pid_cache
            .entry(ev.pid)
            .or_insert_with(|| ffi::process_name_matches(ev.pid, &target_lower));
        if !matches {
            continue;
        }
        match ev.event {
            ffi::FlowEvent::Established => {
                whitelist.insert(ev.local_port, ());
            }
            ffi::FlowEvent::Deleted => {
                whitelist.remove(&ev.local_port);
            }
        }
    }
    info!(rule_id = %rule_id, "FLOW watcher exited");
}
