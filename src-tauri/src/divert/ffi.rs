//! Thin safe wrapper over WinDivert's C ABI, loaded at runtime via LoadLibrary.
//!
//! Loading at runtime (vs link time) lets the app ship without `WinDivert.lib`
//! and resolve symbols from the DLL we download in [`super::bootstrap`].
//!
//! WINDIVERT_ADDRESS layout reference (WinDivert 2.x, 80 bytes):
//!     0..8    INT64  Timestamp
//!     8       UINT8  Layer
//!     9       UINT8  Event
//!     10      UINT8  flags (LSB-first): Sniffed, Outbound, Loopback,
//!                           Impostor, IPv6, IPChecksum, TCPChecksum, UDPChecksum
//!     11      UINT8  Reserved1
//!     12..16  UINT32 Reserved2
//!     16..80  union { Network, Flow, Socket, Reflect, Reserved3[64] }
//!
//! WINDIVERT_DATA_FLOW (relative to start of union, i.e. offset 16):
//!     0..8    EndpointId
//!     8..16   ParentEndpointId
//!     16..20  ProcessId
//!     20..36  LocalAddr  (16 bytes)
//!     36..52  RemoteAddr (16 bytes)
//!     52..54  LocalPort
//!     54..56  RemotePort
//!     56      Protocol

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use anyhow::{anyhow, Result};
use libloading::Library;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::path::Path;
use std::ptr::null_mut;
use std::sync::{Arc, OnceLock};

type HANDLE = *mut std::ffi::c_void;
const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

// WinDivert v2 layer values (windivert.h `WINDIVERT_LAYER`):
//   NETWORK=0, NETWORK_FORWARD=1, FLOW=2, SOCKET=3, REFLECT=4.
pub const LAYER_NETWORK: c_int = 0;
pub const LAYER_FLOW: c_int = 2;

pub const SHUTDOWN_BOTH: c_int = 3;

pub const FLAG_SNIFF: u64 = 0x0001;
// WinDivert flag values (windivert.h):
//   SNIFF=0x01, DROP=0x02, RECV_ONLY=0x04, SEND_ONLY=0x08,
//   NO_INSTALL=0x10, FRAGMENTS=0x20
// FLOW layer is read-only, so it MUST be opened with SNIFF | RECV_ONLY (0x05).
pub const FLAG_RECV_ONLY: u64 = 0x0004;

// WinDivert v2 event values (windivert.h `WINDIVERT_EVENT`):
//   NETWORK_PACKET=0, FLOW_ESTABLISHED=1, FLOW_DELETED=2,
//   SOCKET_BIND=3, SOCKET_CONNECT=4, SOCKET_LISTEN=5, SOCKET_ACCEPT=6,
//   SOCKET_CLOSE=7, REFLECT_OPEN=8, REFLECT_CLOSE=9
pub const EVENT_FLOW_ESTABLISHED: u8 = 1;
pub const EVENT_FLOW_DELETED: u8 = 2;

type FnOpen =
    unsafe extern "system" fn(*const c_char, c_int, i16, u64) -> HANDLE;
type FnRecv =
    unsafe extern "system" fn(HANDLE, *mut u8, u32, *mut u32, *mut u8) -> c_int;
type FnSend =
    unsafe extern "system" fn(HANDLE, *const u8, u32, *mut u32, *const u8) -> c_int;
type FnShutdown = unsafe extern "system" fn(HANDLE, c_int) -> c_int;
type FnClose = unsafe extern "system" fn(HANDLE) -> c_int;
type FnCalcChecksums =
    unsafe extern "system" fn(*mut u8, u32, *mut u8, u64) -> c_int;

struct Api {
    _lib: Library,
    open: FnOpen,
    recv: FnRecv,
    send: FnSend,
    shutdown: FnShutdown,
    close: FnClose,
    calc_checksums: FnCalcChecksums,
}

unsafe impl Send for Api {}
unsafe impl Sync for Api {}

static API: OnceLock<Api> = OnceLock::new();

pub fn is_initialized() -> bool {
    API.get().is_some()
}

/// Load WinDivert.dll from the given path and resolve all entry points.
/// Idempotent — subsequent calls with the same DLL are no-ops.
pub fn init(dll_path: &Path) -> Result<()> {
    if API.get().is_some() {
        return Ok(());
    }
    unsafe {
        let lib = Library::new(dll_path)
            .map_err(|e| anyhow!("LoadLibrary {}: {e}", dll_path.display()))?;
        let open: FnOpen = *lib
            .get::<FnOpen>(b"WinDivertOpen\0")
            .map_err(|e| anyhow!("GetProcAddress WinDivertOpen: {e}"))?;
        let recv: FnRecv = *lib
            .get::<FnRecv>(b"WinDivertRecv\0")
            .map_err(|e| anyhow!("GetProcAddress WinDivertRecv: {e}"))?;
        let send: FnSend = *lib
            .get::<FnSend>(b"WinDivertSend\0")
            .map_err(|e| anyhow!("GetProcAddress WinDivertSend: {e}"))?;
        let shutdown: FnShutdown = *lib
            .get::<FnShutdown>(b"WinDivertShutdown\0")
            .map_err(|e| anyhow!("GetProcAddress WinDivertShutdown: {e}"))?;
        let close: FnClose = *lib
            .get::<FnClose>(b"WinDivertClose\0")
            .map_err(|e| anyhow!("GetProcAddress WinDivertClose: {e}"))?;
        let calc_checksums: FnCalcChecksums = *lib
            .get::<FnCalcChecksums>(b"WinDivertHelperCalcChecksums\0")
            .map_err(|e| anyhow!("GetProcAddress WinDivertHelperCalcChecksums: {e}"))?;
        let api = Api {
            _lib: lib,
            open,
            recv,
            send,
            shutdown,
            close,
            calc_checksums,
        };
        let _ = API.set(api);
    }
    Ok(())
}

fn api() -> &'static Api {
    API.get().expect("divert::ffi::init was not called")
}

#[derive(Debug, Clone, Copy)]
pub enum Layer {
    Network,
    Flow,
}

impl Layer {
    fn as_int(self) -> c_int {
        match self {
            Layer::Network => LAYER_NETWORK,
            Layer::Flow => LAYER_FLOW,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

pub const ADDR_SIZE: usize = 80;

#[derive(Clone, Copy)]
pub struct Address(pub [u8; ADDR_SIZE]);

impl Default for Address {
    fn default() -> Self {
        Self([0; ADDR_SIZE])
    }
}

impl Address {
    #[inline]
    pub fn direction(&self) -> Direction {
        if (self.0[10] & 0b0000_0010) != 0 {
            Direction::Outbound
        } else {
            Direction::Inbound
        }
    }
    #[inline]
    pub fn set_direction(&mut self, d: Direction) {
        match d {
            Direction::Outbound => self.0[10] |= 0b0000_0010,
            Direction::Inbound => self.0[10] &= !0b0000_0010,
        }
    }
    #[inline]
    pub fn is_loopback(&self) -> bool {
        (self.0[10] & 0b0000_0100) != 0
    }
    #[inline]
    pub fn set_loopback(&mut self, on: bool) {
        if on {
            self.0[10] |= 0b0000_0100;
        } else {
            self.0[10] &= !0b0000_0100;
        }
    }
    #[inline]
    pub fn event(&self) -> u8 {
        self.0[9]
    }
    #[inline]
    pub fn flow_pid(&self) -> u32 {
        u32::from_le_bytes(self.0[32..36].try_into().unwrap())
    }
    #[inline]
    pub fn flow_local_port(&self) -> u16 {
        u16::from_le_bytes(self.0[68..70].try_into().unwrap())
    }
    #[inline]
    pub fn flow_remote_port(&self) -> u16 {
        u16::from_le_bytes(self.0[70..72].try_into().unwrap())
    }
    /// IPv4 remote address from a FLOW event. Assumes the address is stored
    /// in the first 4 bytes of the 16-byte slot in network byte order, which
    /// is the WinDivert v2 convention for IPv4 flows. Returns None if the
    /// remaining 12 bytes are non-zero (likely IPv6).
    #[inline]
    pub fn flow_remote_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        let bytes = &self.0[52..68];
        if bytes[4..16].iter().any(|b| *b != 0) {
            return None;
        }
        Some(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    }
    #[inline]
    pub fn flow_local_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        let bytes = &self.0[36..52];
        if bytes[4..16].iter().any(|b| *b != 0) {
            return None;
        }
        Some(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    }
}

#[derive(Clone)]
pub struct DivertHandle {
    inner: Arc<HandleInner>,
}

struct HandleInner {
    h: HANDLE,
}

unsafe impl Send for HandleInner {}
unsafe impl Sync for HandleInner {}

impl Drop for HandleInner {
    fn drop(&mut self) {
        if self.h != INVALID_HANDLE_VALUE && !self.h.is_null() {
            unsafe { (api().close)(self.h) };
        }
    }
}

impl DivertHandle {
    pub fn open(filter: &str, layer: Layer, priority: i16, flags: u64) -> Result<Self> {
        let cfilter = CString::new(filter)?;
        tracing::debug!(layer = ?layer, priority, flags, %filter, "WinDivertOpen");
        let h = unsafe { (api().open)(cfilter.as_ptr(), layer.as_int(), priority, flags) };
        if h == INVALID_HANDLE_VALUE {
            let err = std::io::Error::last_os_error();
            let code = err.raw_os_error().unwrap_or(0);
            let hint = match code {
                5 => "ACCESS DENIED — process must be elevated (run app as Administrator).".to_string(),
                87 => format!(
                    "INVALID PARAMETER — likely a malformed filter string or unsupported layer/flag \
                     combination.\n  layer={:?} priority={} flags={:#x}\n  filter: {}",
                    layer, priority, flags, filter
                ),
                2 => "FILE NOT FOUND — WinDivert64.sys not present next to WinDivert.dll, \
                      or the kernel driver service couldn't be installed."
                    .into(),
                577 => "INVALID IMAGE HASH — WinDivert64.sys signature rejected by Windows. \
                       Try reinstalling WinDivert."
                    .into(),
                _ => String::new(),
            };
            return Err(anyhow!(
                "WinDivertOpen failed (os error {code}): {err}{}{}",
                if hint.is_empty() { "" } else { "\n  " },
                hint
            ));
        }
        Ok(Self {
            inner: Arc::new(HandleInner { h }),
        })
    }

    pub fn open_flow_sniff(filter: &str) -> Result<Self> {
        Self::open(filter, Layer::Flow, 1000, FLAG_SNIFF | FLAG_RECV_ONLY)
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<(usize, Address)> {
        let mut addr = Address::default();
        let mut recv_len: u32 = 0;
        let ok = unsafe {
            (api().recv)(
                self.inner.h,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut recv_len,
                addr.0.as_mut_ptr(),
            )
        };
        if ok == 0 {
            return Err(anyhow!("WinDivertRecv: {}", std::io::Error::last_os_error()));
        }
        Ok((recv_len as usize, addr))
    }

    pub fn send(&self, buf: &[u8], addr: &Address) -> Result<()> {
        let mut send_len: u32 = 0;
        let ok = unsafe {
            (api().send)(
                self.inner.h,
                buf.as_ptr(),
                buf.len() as u32,
                &mut send_len,
                addr.0.as_ptr(),
            )
        };
        if ok == 0 {
            return Err(anyhow!("WinDivertSend: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }

    pub fn shutdown(&self) -> Result<()> {
        let ok = unsafe { (api().shutdown)(self.inner.h, SHUTDOWN_BOTH) };
        if ok == 0 {
            return Err(anyhow!(
                "WinDivertShutdown: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub fn recv_flow(&self) -> Result<FlowEventInfo> {
        let mut addr = Address::default();
        let mut recv_len: u32 = 0;
        let ok = unsafe {
            (api().recv)(
                self.inner.h,
                null_mut(),
                0,
                &mut recv_len,
                addr.0.as_mut_ptr(),
            )
        };
        if ok == 0 {
            return Err(anyhow!(
                "WinDivertRecv(flow): {}",
                std::io::Error::last_os_error()
            ));
        }
        let event = match addr.event() {
            EVENT_FLOW_ESTABLISHED => FlowEvent::Established,
            EVENT_FLOW_DELETED => FlowEvent::Deleted,
            other => return Err(anyhow!("unknown flow event {other}")),
        };
        Ok(FlowEventInfo {
            event,
            pid: addr.flow_pid(),
            local_port: addr.flow_local_port(),
            remote_port: addr.flow_remote_port(),
            remote_ipv4: addr.flow_remote_ipv4(),
            local_ipv4: addr.flow_local_ipv4(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEvent {
    Established,
    Deleted,
}

#[derive(Debug, Clone, Copy)]
pub struct FlowEventInfo {
    pub event: FlowEvent,
    pub pid: u32,
    pub local_port: u16,
    pub remote_port: u16,
    pub remote_ipv4: Option<std::net::Ipv4Addr>,
    pub local_ipv4: Option<std::net::Ipv4Addr>,
}

pub fn calc_checksums(pkt: &mut [u8]) -> Result<()> {
    let ok = unsafe {
        (api().calc_checksums)(pkt.as_mut_ptr(), pkt.len() as u32, null_mut(), 0)
    };
    if ok == 0 {
        return Err(anyhow!(
            "WinDivertHelperCalcChecksums: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

// --- Process-name lookup for the FLOW whitelist -----------------------------

#[cfg(windows)]
pub fn process_name_matches(pid: u32, target_lower: &str) -> bool {
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
pub fn process_name_matches(_pid: u32, _target_lower: &str) -> bool {
    false
}
