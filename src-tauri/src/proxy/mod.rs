pub mod server;
pub mod tls;

use crate::ca::CertAuthority;
use crate::config::{ListenerConfig, Scheme};
use crate::rules::RuleStore;
use crate::storage::History;
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::oneshot;

#[derive(Clone)]
pub struct ProxyDeps {
    pub rules: RuleStore,
    pub history: History,
    pub ca: Arc<CertAuthority>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListenerState {
    Stopped,
    Running,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListenerStatus {
    pub id: String,
    pub scheme: Scheme,
    pub bind: String,
    pub port: u16,
    pub state: ListenerState,
    pub error: Option<String>,
}

#[derive(Default)]
struct ListenerEntry {
    stop_tx: Option<oneshot::Sender<()>>,
    status: ListenerStatus,
}

impl Default for ListenerStatus {
    fn default() -> Self {
        Self {
            id: String::new(),
            scheme: Scheme::Http,
            bind: String::new(),
            port: 0,
            state: ListenerState::Stopped,
            error: None,
        }
    }
}

pub struct ProxyHandle {
    listeners: Mutex<HashMap<String, ListenerEntry>>,
}

impl ProxyHandle {
    pub fn new() -> Self {
        Self {
            listeners: Mutex::new(HashMap::new()),
        }
    }

    pub fn status(&self) -> Vec<ListenerStatus> {
        let g = self.listeners.lock();
        let mut v: Vec<_> = g.values().map(|e| e.status.clone()).collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    pub fn stop_all(&self) {
        let mut g = self.listeners.lock();
        for (_, entry) in g.iter_mut() {
            if let Some(tx) = entry.stop_tx.take() {
                let _ = tx.send(());
            }
            entry.status.state = ListenerState::Stopped;
        }
    }

    pub fn stop_one(&self, id: &str) {
        let mut g = self.listeners.lock();
        if let Some(entry) = g.get_mut(id) {
            if let Some(tx) = entry.stop_tx.take() {
                let _ = tx.send(());
            }
            entry.status.state = ListenerState::Stopped;
        }
    }

    /// Start (or restart) one listener. Returns true if bind succeeded.
    pub async fn start_one(&self, cfg: &ListenerConfig, deps: ProxyDeps) -> bool {
        self.stop_one(&cfg.id);

        let addr = match cfg.addr().parse() {
            Ok(a) => a,
            Err(e) => {
                self.record_failed(cfg, format!("invalid address: {e}"));
                return false;
            }
        };

        let (tx, rx) = oneshot::channel();
        let res = match cfg.scheme {
            Scheme::Http => server::serve_http(cfg.id.clone(), addr, deps, rx).await,
            Scheme::Https => server::serve_https(cfg.id.clone(), addr, deps, rx).await,
        };
        match res {
            Ok(_) => {
                let mut g = self.listeners.lock();
                g.insert(
                    cfg.id.clone(),
                    ListenerEntry {
                        stop_tx: Some(tx),
                        status: ListenerStatus {
                            id: cfg.id.clone(),
                            scheme: cfg.scheme,
                            bind: cfg.bind.clone(),
                            port: cfg.port,
                            state: ListenerState::Running,
                            error: None,
                        },
                    },
                );
                true
            }
            Err(e) => {
                self.record_failed(cfg, format!("{e:#}"));
                false
            }
        }
    }

    fn record_failed(&self, cfg: &ListenerConfig, err: String) {
        let mut g = self.listeners.lock();
        g.insert(
            cfg.id.clone(),
            ListenerEntry {
                stop_tx: None,
                status: ListenerStatus {
                    id: cfg.id.clone(),
                    scheme: cfg.scheme,
                    bind: cfg.bind.clone(),
                    port: cfg.port,
                    state: ListenerState::Failed,
                    error: Some(err),
                },
            },
        );
    }
}
