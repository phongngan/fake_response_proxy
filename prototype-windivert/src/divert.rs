//! Thin safe wrapper over the WinDivert C ABI, loaded at runtime via LoadLibrary.
//!
//! Why runtime loading instead of link-time? So the application can ship
//! without `WinDivert.lib`, download `WinDivert.dll` + `WinDivert64.sys` on
//! first run, and only then resolve symbols. See `bootstrap.rs`.
//!
//! WINDIVERT_ADDRESS layout reference (WinDivert 2.x):
//!     offset  field
//!     0..8    INT64  Timestamp
//!     8       UINT8  Layer
//!     9       UINT8  Event
//!     10      UINT8  flags (LSB-first): Sniffed, Outbound, Loopback,
//!                           Impostor, IPv6, IPChecksum, TCPChecksum, UDPChecksum
//!     11      UINT8  Reserved1
//!     12..16  UINT32 Reserved2
//!     16..80  union { Network, Flow, Socket, Reflect, Reserved3[64] }
//!
//! WINDIVERT_DATA_FLOW (offset 16 within WINDIVERT_ADDRESS):
//!     16+0  ..16+8   EndpointId
//!     16+8  ..16+16  ParentEndpointId
//!     16+16 ..16+20  ProcessId
//!     16+20 ..16+36  LocalAddr  [16 bytes]
//!     16+36 ..16+52  RemoteAddr [16 bytes]
//!     16+52 ..16+54  LocalPort
//!     16+54 ..16+56  RemotePort
//!     16+56          Protocol

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

pub const LAYER_NETWORK: c_int = 0;
pub const LAYER_FLOW: c_int = 4;

pub const SHUTDOWN_BOTH: c_int = 3;

pub const FLAG_SNIFF: u64 = 0x0001;
pub const FLAG_RECV_ONLY: u64 = 0x0004; // SEND_ONLY would be 0x0008

pub const EVENT_FLOW_ESTABLISHED: u8 = 4;
pub const EVENT_FLOW_DELETED: u8 = 5;

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

/// Load `WinDivert.dll` from the given path and resolve all entry points.
/// Idempotent.
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
    API.get().expect("divert::init was not called")
}

// --- Layer / Direction enums --------------------------------------------

#[derive(Debug, Clone, Copy)]
pub enum Layer {
    Network,
    #[allow(dead_code)]
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

// --- Address wrapper ----------------------------------------------------

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
}

// --- Handle wrapper -----------------------------------------------------

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
        let h = unsafe { (api().open)(cfilter.as_ptr(), layer.as_int(), priority, flags) };
        if h == INVALID_HANDLE_VALUE {
            let err = std::io::Error::last_os_error();
            return Err(anyhow!(
                "WinDivertOpen failed: {err}. Process must be elevated and the \
                 WinDivert kernel driver must be installable (sys file next to dll)."
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
