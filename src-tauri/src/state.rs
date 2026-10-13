use crate::ca::CertAuthority;
use crate::config::AppConfig;
use crate::divert::{Prober, RedirectorHandle};
use crate::proxy::ProxyHandle;
use crate::rules::RuleStore;
use crate::storage::History;
use parking_lot::RwLock;
use std::sync::Arc;

pub struct AppState {
    pub config: Arc<RwLock<AppConfig>>,
    pub rules: RuleStore,
    pub history: History,
    pub ca: Arc<CertAuthority>,
    pub proxy: Arc<ProxyHandle>,
    pub redirector: Arc<RedirectorHandle>,
    pub prober: Arc<Prober>,
}
