//! Dynamic per-SNI cert resolver backed by the CA.

use crate::ca::CertAuthority;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;

#[derive(Debug)]
pub struct DynamicResolver {
    ca: Arc<CertAuthority>,
}

impl DynamicResolver {
    pub fn new(ca: Arc<CertAuthority>) -> Self {
        Self { ca }
    }
}

impl ResolvesServerCert for DynamicResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Clients connecting via IP (e.g. `curl https://127.0.0.1`) do not
        // send SNI. Fall back to a special key for a cert that covers
        // localhost + loopback IPs.
        let sni = client_hello.server_name().unwrap_or("__local__");
        match self.ca.cert_for(sni) {
            Ok(ck) => Some(ck),
            Err(e) => {
                tracing::warn!("cert_for({sni}) failed: {e:#}");
                None
            }
        }
    }
}
