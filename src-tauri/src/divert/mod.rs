//! WinDivert-based TCP redirector.
//!
//! Modules:
//! - [`ffi`]: thin safe wrapper over WinDivert's C ABI, loaded at runtime via
//!   `LoadLibrary` so the app can ship without `WinDivert.lib`.
//! - [`bootstrap`]: download/verify/extract the WinDivert release zip into
//!   `%ProgramData%\FakeResponseProxy\windivert`.
//! - [`redirector`]: [`RedirectorHandle`] manages per-rule NAT threads.

pub mod bootstrap;
pub mod ffi;
pub mod probe;
pub mod redirector;

pub use probe::{ProbeHit, ProbeRequest, ProbeStatus, Prober};
pub use redirector::{RedirectStatus, RedirectorHandle, RuleRuntimeState};
