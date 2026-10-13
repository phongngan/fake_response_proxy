//! Passive process discovery via WinDivert FLOW layer.
//!
//! Given a target (host/IP and/or port) the prober opens a sniff-only handle
//! at the FLOW layer and logs every `ESTABLISHED` event whose remote endpoint
//! matches. For each event we resolve `processId` to an image name via
//! `QueryFullProcessImageNameW`. Unlike per-rule whitelisting, timing here is
//! irrelevant — we're not rewriting anything, just answering "which process
//! talked to X".

use crate::divert::{bootstrap, ffi, redirector::RedirectorHandle};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tracing::{debug, info, warn};

const MAX_HITS: usize = 500;

#[derive(Debug, Clone, Serialize)]
pub struct ProbeHit {
    pub ts: DateTime<Utc>,
    pub event: String, // "established" | "deleted"
    pub pid: u32,
    pub process_name: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRequest {
    /// Comma-separated targets: IPv4 literal or hostname. Empty = match any IP.
    #[serde(default)]
    pub target: String,
    /// Optional remote port filter. 0 / None = any.
    #[serde(default)]
    pub port: Option<u16>,
    /// If true, also log FLOW_DELETED events (verbose).
    #[serde(default)]
    pub include_deleted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeStatus {
    pub running: bool,
    pub target: String,
    pub port: Option<u16>,
    pub include_deleted: bool,
    pub resolved_targets: Vec<String>,
    pub filter: String,
    pub hits: Vec<ProbeHit>,
}

struct ProbeInner {
    handle: ffi::DivertHandle,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    request: ProbeRequest,
    resolved_targets: Vec<Ipv4Addr>,
    filter: String,
}

pub struct Prober {
    inner: Mutex<Option<ProbeInner>>,
    hits: Arc<Mutex<VecDeque<ProbeHit>>>,
}

impl Prober {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
            hits: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_HITS))),
        }
    }

    pub fn status(&self) -> ProbeStatus {
        let inner = self.inner.lock();
        let running = inner.is_some();
        let (target, port, include_deleted, resolved, filter) = match inner.as_ref() {
            Some(i) => (
                i.request.target.clone(),
                i.request.port,
                i.request.include_deleted,
                i.resolved_targets.iter().map(|ip| ip.to_string()).collect(),
                i.filter.clone(),
            ),
            None => (String::new(), None, false, Vec::new(), String::new()),
        };
        drop(inner);
        let hits = self.hits.lock();
        let hits_vec: Vec<ProbeHit> = hits.iter().cloned().collect();
        ProbeStatus {
            running,
            target,
            port,
            include_deleted,
            resolved_targets: resolved,
            filter,
            hits: hits_vec,
        }
    }

    pub fn start(&self, req: ProbeRequest, redirector: &RedirectorHandle) -> Result<()> {
        // Stop any previous probe first.
        self.stop();
        // Ensure WinDivert installed + DLL loaded.
        redirector.ensure_ready()?;

        let resolved_targets = resolve_targets(&req.target)?;
        if !req.target.trim().is_empty() && resolved_targets.is_empty() {
            return Err(anyhow!(
                "target '{}' resolved to no IPv4 addresses",
                req.target
            ));
        }
        let filter = build_filter(&resolved_targets, req.port, req.include_deleted);
        info!(filter = %filter, "opening WinDivert FLOW prober");
        let handle = ffi::DivertHandle::open_flow_sniff(&filter)?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = stop.clone();
        let handle_w = handle.clone();
        let hits = self.hits.clone();
        let include_deleted = req.include_deleted;
        let thread = std::thread::Builder::new()
            .name("frp-probe".into())
            .spawn(move || probe_loop(handle_w, hits, stop_w, include_deleted))?;

        *self.inner.lock() = Some(ProbeInner {
            handle,
            stop,
            thread: Some(thread),
            request: req,
            resolved_targets,
            filter,
        });
        Ok(())
    }

    pub fn stop(&self) {
        let inner = self.inner.lock().take();
        let Some(mut inner) = inner else { return };
        inner.stop.store(true, Ordering::SeqCst);
        let _ = inner.handle.shutdown();
        if let Some(t) = inner.thread.take() {
            let _ = t.join();
        }
        info!("probe stopped");
    }

    pub fn clear_hits(&self) {
        self.hits.lock().clear();
    }
}

fn probe_loop(
    handle: ffi::DivertHandle,
    hits: Arc<Mutex<VecDeque<ProbeHit>>>,
    stop: Arc<AtomicBool>,
    include_deleted: bool,
) {
    let pid_cache: DashMap<u32, String> = DashMap::new();
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
        if !include_deleted && ev.event != ffi::FlowEvent::Established {
            continue;
        }
        let event = match ev.event {
            ffi::FlowEvent::Established => "established".to_string(),
            ffi::FlowEvent::Deleted => "deleted".to_string(),
        };
        let process_name = pid_cache
            .entry(ev.pid)
            .or_insert_with(|| process_image_name(ev.pid).unwrap_or_else(|| "<unknown>".into()))
            .clone();
        let hit = ProbeHit {
            ts: Utc::now(),
            event,
            pid: ev.pid,
            process_name,
            local_addr: ev
                .local_ipv4
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "?".into()),
            local_port: ev.local_port,
            remote_addr: ev
                .remote_ipv4
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "?".into()),
            remote_port: ev.remote_port,
        };
        debug!(?hit, "probe hit");
        let mut h = hits.lock();
        if h.len() >= MAX_HITS {
            h.pop_front();
        }
        h.push_back(hit);
    }
    info!("probe loop exited");
}

fn build_filter(targets: &[Ipv4Addr], port: Option<u16>, include_deleted: bool) -> String {
    let mut clauses: Vec<String> = Vec::new();
    if include_deleted {
        clauses.push("(event == ESTABLISHED or event == DELETED)".into());
    } else {
        clauses.push("event == ESTABLISHED".into());
    }
    clauses.push("protocol == 6".into()); // TCP
    if let Some(p) = port {
        if p != 0 {
            clauses.push(format!("remotePort == {p}"));
        }
    }
    if !targets.is_empty() {
        let ors = targets
            .iter()
            .map(|ip| format!("remoteAddr == {ip}"))
            .collect::<Vec<_>>()
            .join(" or ");
        clauses.push(format!("({ors})"));
    }
    clauses.join(" and ")
}

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

#[cfg(windows)]
fn process_image_name(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len: u32 = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        let basename = path
            .rsplit(|c| c == '\\' || c == '/')
            .next()
            .unwrap_or(&path)
            .to_string();
        Some(basename)
    }
}

#[cfg(not(windows))]
fn process_image_name(_pid: u32) -> Option<String> {
    None
}

// Bootstrap reference kept to silence dead-code warning if bootstrap is unused
// from this module; it's pulled in transitively via redirector's API.
#[allow(dead_code)]
fn _bootstrap_link() -> &'static str {
    bootstrap::WINDIVERT_VERSION
}
